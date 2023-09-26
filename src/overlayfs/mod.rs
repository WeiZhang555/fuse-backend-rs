#![allow(missing_docs)]
//#![feature(io_error_more)]

pub mod config;
pub mod direct;
pub mod layer;
pub mod sync_io;
mod utils;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Result, Seek, SeekFrom};
use std::mem::MaybeUninit;
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::abi::fuse_abi::{CreateIn, ROOT_ID as FUSE_ROOT_ID};
use crate::api::filesystem::{
    Context, DirEntry, Entry, OpenOptions, ZeroCopyReader, ZeroCopyWriter,
};
use crate::api::{SLASH_ASCII, VFS_MAX_INO};

use crate::common::file_buf::FileVolatileSlice;
use crate::common::file_traits::FileReadWriteVolatile;

use self::config::Config;
use self::layer::Layer;
use libc;
use std::io::{Error, ErrorKind};

pub type Inode = u64;
pub type Handle = u64;
pub const PLUGIN_PREFIX: &str = "//";
pub const XATTR_PREFIX: &str = "user.fuseoverlayfs";
pub const ORIGIN_XATTR: &str = "user.fuseoverlayfs.origin";
pub const OPAQUE_XATTR: &str = "user.fuseoverlayfs.opaque";
pub const XATTR_CONTAINERS_PREFIX: &str = "user.containers";
pub const UNPRIVILEGED_XATTR_PREFIX: &str = "user.overlay";
pub const UNPRIVILEGED_OPAQUE_XATTR: &str = "user.overlay.opaque";
pub const PRIVILEGED_XATTR_PREFIX: &str = "trusted.overlay";
pub const PRIVILEGED_OPAQUE_XATTR: &str = "trusted.overlay.opaque";
pub const PRIVILEGED_ORIGIN_XATTR: &str = "trusted.overlay.origin";
pub const MAXNAMELEN: usize = 256;
pub const CURRENT_DIR: &str = ".";
pub const PARENT_DIR: &str = "..";
pub const MAXBUFSIZE: usize = 1 << 20;

// need real inode from layers, need inode to do layer
// operations
#[derive(Default)]
pub struct RealInode {
    // TODO: make this required field. @fangcun.zw
    pub layer: Option<Arc<Box<Layer>>>,
    pub inode: AtomicU64,
    // File is whiteouted, we need to hide it.
    pub whiteout: AtomicBool,
    // Directory is opaque, we need to hide all entries inside it.
    pub opaque: AtomicBool,
    pub hidden: AtomicBool,
    pub invalid: AtomicBool,
}

#[derive(Default, Debug)]
pub struct RealInodeStats {
    pub inode: u64,
    pub whiteout: bool,
    pub opaque: bool,
    pub stat: Option<libc::stat64>,
}

#[derive(Default)]
pub struct OverlayInode {
    // Inode hash table, map from 'name' to 'OverlayInode'.
    pub childrens: Mutex<HashMap<String, Arc<OverlayInode>>>,
    pub parent: Mutex<Weak<OverlayInode>>,
    // Backend inodes from all low layers.
    pub lower_inodes: Vec<Arc<RealInode>>,
    // Backend inode from upper layer.
    pub upper_inode: Mutex<Option<Arc<RealInode>>>,
    // Inode number.
    pub inode: u64,
    pub st_ino: libc::ino64_t,
    pub st_dev: libc::dev_t,
    pub mode: libc::mode_t,
    pub entry_type: u32,
    pub path: String,
    pub name: String,
    pub lookups: Mutex<u64>,

    pub hidden: AtomicBool,
    // Node is whiteout-ed.
    pub whiteout: AtomicBool,
    pub loaded: AtomicBool,
    // what about data source related data for each inode
    // put it into layer struct, ino -> private data hash
}

pub enum CachePolicy {
    Never,
    Auto,
    Always,
}

pub struct OverlayFs {
    // should be in daemon structure
    pub config: Config,
    pub lower_layers: Vec<Arc<Box<Layer>>>,
    pub upper_layer: Option<Arc<Box<Layer>>>,
    // inode management..
    pub root: Option<Arc<OverlayInode>>,
    pub inodes: Mutex<HashMap<u64, Arc<OverlayInode>>>,
    pub next_inode: AtomicU64,

    // manage opened fds..
    pub handles: Mutex<HashMap<u64, HandleData>>,
    pub next_handle: AtomicU64,
    pub writeback: AtomicBool,
    pub no_open: AtomicBool,
    pub no_opendir: AtomicBool,
    pub killpriv_v2: AtomicBool,
    pub perfile_dax: AtomicBool,
}

pub struct RealHandle {
    pub real_inode: Arc<RealInode>,
    pub handle: AtomicU64,
    pub invalid: AtomicBool,
}

pub struct HandleData {
    pub node: Arc<OverlayInode>,
    pub childrens: Option<Vec<Arc<OverlayInode>>>,
    pub offset: libc::off_t,

    // others?
    pub real_handle: Option<RealHandle>,
}

impl RealInode {
    pub fn stat64_ignore_enoent(&self, ctx: &Context) -> Result<Option<libc::stat64>> {
        if self.invalid.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let layer = self.layer.as_ref();
        match layer
            .ok_or(Error::from_raw_os_error(libc::EINVAL))?
            .fs()
            .getattr(ctx, self.inode.load(Ordering::Relaxed), None)
        {
            Ok((v1, _v2)) => {
                return Ok(Some(v1));
            }

            Err(e) => match e.raw_os_error() {
                Some(raw_error) => {
                    if raw_error != libc::ENOENT
                        && raw_error != libc::ENOTDIR
                        && raw_error != libc::ENAMETOOLONG
                    {
                        return Ok(None);
                    }
                    return Err(e);
                }

                None => {
                    return Err(e);
                }
            },
        }
    }

    // Find child real-inode under this directory(Self).
    // Return None if not found.
    pub fn lookup_node(&self, ctx: &Context, name: &str) -> Result<Option<RealInodeStats>> {
        if self.whiteout.load(Ordering::Relaxed) || self.invalid.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let layer = self
            .layer
            .as_ref()
            .ok_or(Error::from_raw_os_error(libc::EINVAL))?;
        let inode = self.inode.load(Ordering::Relaxed);
        let whiteout = layer.is_whiteout(ctx, inode)?;

        // The inode is whiteout-ed, return directly.
        if whiteout {
            return Ok(Some(RealInodeStats {
                inode,
                whiteout,
                opaque: false,
                stat: None,
            }));
        }

        // Find Entry with <name> under directory with inode <self.inode>.
        match layer.lookup_ignore_enoent(ctx, self.inode.load(Ordering::Relaxed), name)? {
            Some(v) => {
                // Not directory.
                if !utils::is_dir(v.attr) {
                    return Ok(Some(RealInodeStats {
                        inode: v.inode,
                        // Check if it's whiteouted.
                        whiteout: layer.is_whiteout(ctx, v.inode)?,
                        opaque: false,
                        stat: Some(v.attr),
                    }));
                }

                // For directory.
                Ok(Some(RealInodeStats {
                    inode: v.inode,
                    whiteout: false,
                    // Check if directory is opaque.
                    opaque: layer.is_opaque_whiteout(ctx, v.inode)?,
                    stat: Some(v.attr),
                }))
            }
            None => Ok(None),
        }
    }
}

impl OverlayInode {
    pub fn stat64(&self, ctx: &Context) -> Result<libc::stat64> {
        // try upper layer if there is
        if let Some(ref l) = *self.upper_inode.lock().unwrap() {
            if let Some(v) = l.stat64_ignore_enoent(ctx)? {
                return Ok(v);
            }
        }

        // try layers in order or just take stst from first layer?
        for l in &self.lower_inodes {
            if let Some(v) = l.stat64_ignore_enoent(ctx)? {
                return Ok(v);
            }
        }

        // not in any layer
        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    pub fn count_entries_and_whiteout(&self, ctx: &Context) -> Result<(u64, u64, u64)> {
        let mut count = 0;
        let mut whiteouts = 0;
        let mut opaque = 0;

        let st = self.stat64(ctx)?;

        // must be directory
        if !utils::is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        // FIXME: should we remove this? @fangcun.zw
        if let Some(ri) = self.upper_inode.lock().unwrap().as_ref() {
            if ri.opaque.load(Ordering::Relaxed) {
                opaque = 1;
            }
        }

        for (_, child) in self.childrens.lock().unwrap().iter() {
            if child.whiteout.load(Ordering::Relaxed) {
                whiteouts += 1;
            } else {
                count += 1;
            }
        }

        Ok((count, whiteouts, opaque))
    }

    pub fn open(
        &self,
        ctx: &Context,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<(Arc<Box<Layer>>, Option<Handle>, OpenOptions)> {
        let ri = &self.first_inode();
        if let Some(ref l) = ri.layer {
            let (h, o) = l
                .fs()
                .open(ctx, ri.inode.load(Ordering::Relaxed), flags, fuse_flags)?;
            Ok((Arc::clone(l), h, o))
        } else {
            Err(Error::new(ErrorKind::Other, "no first layer"))
        }
    }

    pub fn in_upper_layer(&self) -> bool {
        self.upper_inode.lock().unwrap().is_some()
    }

    pub fn upper_layer_only(&self) -> bool {
        self.lower_inodes.len() == 0
    }

    pub fn first_inode(&self) -> Arc<RealInode> {
        match self.upper_inode.lock().unwrap().as_ref() {
            Some(v) => Arc::clone(v),
            None => Arc::clone(&self.lower_inodes[0]),
        }
    }
}

impl OverlayInode {
    pub fn new() -> Self {
        OverlayInode::default()
    }
}

fn entry_type_from_mode(mode: libc::mode_t) -> u8 {
    if mode & libc::S_IFBLK != 0 {
        return libc::DT_BLK;
    }

    if mode & libc::S_IFCHR != 0 {
        return libc::DT_CHR;
    }

    if mode & libc::S_IFDIR != 0 {
        return libc::DT_DIR;
    }

    if mode & libc::S_IFIFO != 0 {
        return libc::DT_FIFO;
    }

    if mode & libc::S_IFLNK != 0 {
        return libc::DT_LNK;
    }

    if mode & libc::S_IFREG != 0 {
        return libc::DT_REG;
    }

    if mode & libc::S_IFSOCK != 0 {
        return libc::DT_SOCK;
    }

    return libc::DT_UNKNOWN;
}

impl OverlayFs {
    pub fn new(
        upper: Option<Arc<Box<Layer>>>,
        lowers: Vec<Arc<Box<Layer>>>,
        params: Config,
    ) -> Result<Self> {
        // load root inode
        Ok(OverlayFs {
            config: params,
            lower_layers: lowers,
            upper_layer: upper,
            inodes: Mutex::new(HashMap::new()),
            root: None,
            next_inode: AtomicU64::new(FUSE_ROOT_ID + 1),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            writeback: AtomicBool::new(false),
            no_open: AtomicBool::new(false),
            no_opendir: AtomicBool::new(false),
            killpriv_v2: AtomicBool::new(false),
            perfile_dax: AtomicBool::new(false),
        })
    }

    pub fn init_root(&mut self) -> Result<()> {
        let mut root = OverlayInode::new();
        root.inode = FUSE_ROOT_ID;
        root.path = String::from("");
        root.name = String::from("");
        root.entry_type = libc::DT_DIR as u32;
        root.lookups = Mutex::new(2);
        let ctx = Context::default();

        // Update upper inode
        if let Some(l) = self.upper_layer.as_ref() {
            let real = Arc::new(RealInode {
                layer: Some(Arc::clone(l)),
                inode: AtomicU64::new(FUSE_ROOT_ID),
                whiteout: AtomicBool::new(false),
                opaque: AtomicBool::new(false),
                hidden: AtomicBool::new(false),
                invalid: AtomicBool::new(false),
            });
            root.upper_inode = Mutex::new(Some(real.clone()));
        }

        // Update lower inodes.
        for layer in self.lower_layers.iter() {
            let opaque = layer.is_opaque_whiteout(&ctx, FUSE_ROOT_ID)?;
            let real = RealInode {
                layer: Some(Arc::clone(layer)),
                inode: AtomicU64::new(FUSE_ROOT_ID),
                whiteout: AtomicBool::new(false),
                opaque: AtomicBool::new(opaque),
                hidden: AtomicBool::new(false),
                invalid: AtomicBool::new(false),
            };

            let real_inode = Arc::new(real);
            root.lower_inodes.push(Arc::clone(&real_inode));
        }

        let root_node = Arc::new(root);

        // insert root inode into hash
        self.inode_add(FUSE_ROOT_ID, Arc::clone(&root_node));

        info!("loading root directory\n");
        self.load_directory(&ctx, Arc::clone(&root_node))?;

        self.root = Some(root_node);

        Ok(())
    }

    pub fn import(&self) -> Result<()> {
        Ok(())
    }

    pub fn make_overlay_inode(
        &self,
        ris: &RealInodeStats,
        layer: Arc<Box<Layer>>,
    ) -> Result<OverlayInode> {
        let mut new = OverlayInode::new();
        new.whiteout.store(ris.whiteout, Ordering::Relaxed);
        let real_inode = Arc::new(RealInode {
            layer: Some(Arc::clone(&layer)),
            inode: AtomicU64::new(ris.inode),
            whiteout: AtomicBool::new(ris.whiteout),
            opaque: AtomicBool::new(ris.opaque),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        new.lookups = Mutex::new(1);
        if layer.is_upper() {
            new.upper_inode = Mutex::new(Some(Arc::clone(&real_inode)));
        }

        // FIXME: inode can be reclaimed, we need a better inode allocator. @fangcun.zw
        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        if inode > VFS_MAX_INO {
            error!("reached maximum inode number: {}", VFS_MAX_INO);
            // FIXME: try to reclaim! @fangcun.zw
            return Err(Error::new(
                ErrorKind::Other,
                format!("maximum inode number {} reached", VFS_MAX_INO),
            ));
        }
        new.inode = inode;
        if let Some(st) = ris.stat {
            new.st_ino = st.st_ino;
            new.st_dev = st.st_dev;
            new.mode = st.st_mode;
            new.entry_type = entry_type_from_mode(st.st_mode) as u32;
        }

        Ok(new)
    }

    fn inode_add(&self, inode: u64, node: Arc<OverlayInode>) {
        self.inodes.lock().unwrap().insert(inode, node);
    }

    fn inode_get(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        self.inodes
            .lock()
            .unwrap()
            .get(&inode)
            .map(|v| Arc::clone(v))
    }

    fn inode_remove(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        self.inodes.lock().unwrap().remove(&inode)
    }

    // Lookup child OverlayInode with <name> under <parent> directory.
    // If name is empty, return parent itself.
    pub fn lookup_node(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &str,
    ) -> Result<Arc<OverlayInode>> {
        if name.contains(&[SLASH_ASCII as char]) {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        // Parent inode is expected to be loaded before this function is called.
        let pnode = match self.inode_get(parent) {
            Some(v) => v,
            // No parent inode indicates an internal bug.
            None => return Err(Error::from_raw_os_error(libc::EINVAL)),
        };

        // Parent is whiteout-ed, return ENOENT.
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // Current dir
        if name.eq(".")  
            // Root directory has no parent.
            || (parent == FUSE_ROOT_ID && name.eq("..")) 
            // Special convention: empty name indicates current dir.
            || name.is_empty()
        {
            return Ok(Arc::clone(&pnode));
        }

        // Child is found.
        if let Some(v) = pnode.childrens.lock().unwrap().get(name) {
            return Ok(Arc::clone(v));
        }

        // If the directory is already loaded, return ENOENT directly.
        if pnode.loaded.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // Start to scan the directory.
        let path = format!("{}/{}", pnode.path, name);

        let mut node_inited: bool = false;
        let mut new = OverlayInode::new();

        // Lookup until meet whiteout/opaque-whiteout/file in lower layer.

        // Find it in upper layer.
        let a = pnode.upper_inode.lock().unwrap();
        if let Some(ri) = a.as_ref() {
            // find an entry
            if let Some(ris) = ri.lookup_node(ctx, name)? {
                node_inited = true;
                new = self.make_overlay_inode(&ris, Arc::clone(ri.layer.as_ref().unwrap()))?;
            }
        }

        'layer_loop: for ri in &pnode.lower_inodes {
            // Find an entry.
            if let Some(ris) = ri.lookup_node(ctx, name)? {
                // TODO: remove unwrap(). @fangcun.zw
                let layer = Arc::clone(ri.layer.as_ref().unwrap());
                let real_inode = Arc::new(RealInode {
                    layer: Some(Arc::clone(&layer)),
                    inode: AtomicU64::new(ris.inode),
                    whiteout: AtomicBool::new(ris.whiteout),
                    hidden: AtomicBool::new(false),
                    opaque: AtomicBool::new(ris.opaque),
                    invalid: AtomicBool::new(false),
                });

                // TODO: 这部分看起来很有问题。  @fangcun.zw
                if !node_inited {
                    node_inited = true;
                    new = self.make_overlay_inode(&ris, Arc::clone(&layer))?;
                    new.lower_inodes.push(Arc::clone(&real_inode));

                    // This is whiteout, no need to check lower layers.
                    if ris.whiteout {
                        break 'layer_loop;
                    }

                    // not whiteout, must have stat
                    let st = ris.stat.ok_or(Error::from_raw_os_error(libc::EINVAL))?;
                    // A non-directory file shadows all lower layers as default.
                    if !utils::is_dir(st) {
                        break 'layer_loop;
                    }

                    // Opaque directory shadows all lower layers.
                    if ris.opaque {
                        break 'layer_loop;
                    }
                } else {
                    // should stop?
                    if ris.whiteout {
                        break 'layer_loop;
                    }

                    // not whiteout, must have stat
                    let st = ris.stat.ok_or(Error::from_raw_os_error(libc::EINVAL))?;
                    if !utils::is_dir(st) {
                        break 'layer_loop;
                    }

                    // directory
                    new.lower_inodes.push(Arc::clone(&real_inode));

                    // opaque?
                    if ris.opaque {
                        break 'layer_loop;
                    }
                }
            }
        }

        if node_inited {
            new.path = String::from(path.as_str());
            new.name = String::from(name);
            // set its parent node
            new.parent = Mutex::new(Arc::downgrade(&pnode));
            // insert node into hashs
            let new_node = Arc::new(new);
            self.inode_add(new_node.inode as u64, Arc::clone(&new_node));
            pnode
                .childrens
                .lock()
                .unwrap()
                .insert(name.to_string(), Arc::clone(&new_node));
            return Ok(Arc::clone(&new_node));
        }

        // return specific errors?
        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    pub fn lookup_node_ignore_enoent(
        &self,
        ctx: &Context,
        parent: u64,
        name: &str,
    ) -> Result<Option<Arc<OverlayInode>>> {
        match self.lookup_node(ctx, parent, name) {
            Ok(n) => {
                return Ok(Some(Arc::clone(&n)));
            }

            Err(e) => {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::ENOENT {
                        return Ok(None);
                    }
                }
                return Err(e);
            }
        }
    }

    pub fn get_node_from_inode(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        if let Some(v) = self.inode_get(inode) {
            return Some(v);
        }

        return None;
    }

    // Load directory entries from one specific layer, layer can be upper or some one of lower layers.
    pub fn load_directory_layer(
        &self,
        ctx: &Context,
        ovl_inode: u64,
        real: Arc<RealInode>,
    ) -> Result<()> {
        if real.whiteout.load(Ordering::Relaxed) || real.invalid.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if let Some(st) = real.stat64_ignore_enoent(ctx)? {
            if !utils::is_dir(st) {
                return Err(Error::from_raw_os_error(libc::ENOTDIR));
            }

            // process this directory
            let l = Arc::clone(real.layer.as_ref().unwrap());
            let rinode = real.inode.load(Ordering::Relaxed);

            // Open the directory and load each entry.
            let handle = if let (Some(h), _) = l.fs().opendir(ctx, rinode, libc::O_RDONLY as u32)? {
                h
            } else {
                return Err(Error::new(ErrorKind::Other, "no dir handle"));
            };

            let mut more = true;
            let mut offset = 0;
            let bufsize = 1024;
            while more {
                more = false;
                l.fs().readdir(
                    ctx,
                    rinode,
                    handle,
                    bufsize,
                    offset,
                    &mut |d| -> Result<usize> {
                        more = true;
                        offset = d.offset;
                        let child_name = String::from_utf8_lossy(d.name).into_owned();

                        debug!("entry: {}", child_name.as_str());

                        if child_name.eq(CURRENT_DIR) || child_name.eq(PARENT_DIR) {
                            return Ok(1);
                        }

                        self.lookup_node(ctx, ovl_inode, child_name.as_str())?;

                        Ok(1)
                    },
                )?;
            }

            l.fs()
                .releasedir(ctx, rinode, libc::O_RDONLY as u32, handle)?;
        } else {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        Ok(())
    }

    pub fn load_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        let tmp_ui = {
            if let Some(ref v) = *node.upper_inode.lock().unwrap() {
                Some(Arc::clone(v))
            } else {
                None
            }
        };

        if let Some(ref ui) = tmp_ui {
            debug!("load upper for '{}'", node.path.as_str());
            // upper layer
            if ui.whiteout.load(Ordering::Relaxed) || ui.invalid.load(Ordering::Relaxed) {
                debug!("directory is whiteout or invalid");
                return Ok(());
            }

            if let Some(st) = ui.stat64_ignore_enoent(ctx)? {
                if !utils::is_dir(st) {
                    debug!("it's not a directory");
                    // not directory
                    return Ok(());
                }

                // process this layer
                self.load_directory_layer(ctx, node.inode, Arc::clone(ui))?;
            }

            // if opaque, stop here
            if ui.opaque.load(Ordering::Relaxed) {
                node.loaded.store(true, Ordering::Relaxed);
                debug!("directory is opaque");
                return Ok(());
            }
        }

        // read out directories from each layer
        let mut counter = 1;
        'layer_loop: for ri in &node.lower_inodes {
            debug!("loading lower {} for '{}'", counter, node.path.as_str());
            counter += 1;
            if ri.whiteout.load(Ordering::Relaxed) || ri.invalid.load(Ordering::Relaxed) {
                break 'layer_loop;
            }

            if let Some(st) = ri.stat64_ignore_enoent(ctx)? {
                if !utils::is_dir(st) {
                    // not directory
                    break 'layer_loop;
                }

                // process this layer
                match self.load_directory_layer(ctx, node.inode, Arc::clone(ri)) {
                    Ok(_) => {}
                    Err(e) => {
                        if let Some(raw_error) = e.raw_os_error() {
                            if raw_error == libc::ENOENT {
                                continue 'layer_loop;
                            }
                        }

                        return Err(e);
                    }
                }
            }

            // if opaque, stop here
            if ri.opaque.load(Ordering::Relaxed) {
                break 'layer_loop;
            }
        }

        node.loaded.store(true, Ordering::Relaxed);

        Ok(())
    }

    pub fn reload_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        if node.loaded.load(Ordering::Relaxed) {
            return Ok(());
        }
        {
            let mut children = node.childrens.lock().unwrap();
            *children = HashMap::new();
        }

        self.load_directory(ctx, node)
    }

    pub fn get_first_lower_layer(&self) -> Option<Arc<Box<Layer>>> {
        if self.lower_layers.len() > 0 {
            Some(Arc::clone(&self.lower_layers[0]))
        } else {
            None
        }
    }

    pub fn get_first_layer(&self) -> Option<Arc<Box<Layer>>> {
        if let Some(ref l) = self.upper_layer {
            return Some(Arc::clone(l));
        }

        self.get_first_lower_layer()
    }

    pub fn forget_one(&self, inode: Inode, count: u64) {
        if inode == FUSE_ROOT_ID || inode == 0 {
            return;
        }

        let v = {
            if let Some(n) = self.inode_get(inode) {
                n
            } else {
                return;
            }
        };
        // lock up lookups
        let mut lookups = v.lookups.lock().unwrap();

        if *lookups < count {
            *lookups = 0;
        } else {
            *lookups -= count;
        }

        // remove it from hashmap

        if *lookups == 0 {
            let _ = self.inode_remove(inode);
            let parent = v.parent.lock().unwrap();

            if let Some(p) = parent.upgrade() {
                p.childrens.lock().unwrap().remove(v.name.as_str());
                p.loaded.store(true, Ordering::Relaxed);
            }
        }

        // FIXME: is it possible that the inode still in childrens map?
    }

    pub fn do_statvfs(&self, ctx: &Context, inode: Inode) -> Result<libc::statvfs64> {
        if let Some(v) = self.get_first_layer() {
            if let Ok(sfs) = v.fs().statfs(ctx, inode) {
                return Ok(sfs);
            }
        }

        // otherwise stat on mountpoint
        let mut sfs = MaybeUninit::<libc::statvfs64>::zeroed();
        // FIXME: mountpoint may not exists at all. @fangcun.zw
        let cpath = utils::to_cstring(self.config.mountpoint.as_str())?;
        let path = cpath.as_c_str().as_ptr();

        match unsafe { libc::statvfs64(path, sfs.as_mut_ptr()) } {
            0 => {
                let sfs = unsafe { sfs.assume_init() };
                Ok(sfs)
            }

            _ => Err(Error::last_os_error()),
        }
    }

    pub fn get_fs_namemax(&self, ctx: &Context) -> u64 {
        match self.do_statvfs(ctx, FUSE_ROOT_ID) {
            Ok(sfs) => sfs.f_namemax,
            Err(_) => 255,
        }
    }

    pub fn do_readdir(
        &self,
        ctx: &Context,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        trace!(
            "do_reddir: handle: {}, size: {}, offset: {}",
            handle,
            size,
            offset
        );
        if size == 0 {
            return Ok(());
        }

        // FIXME: if offset == 0, need to reconstruct dir for this handle
        // if offset == 0 {
        // reconstruct directory
        // }

        // lookup the directory
        if let Some(dir) = self.handles.lock().unwrap().get(&handle) {
            let mut len: usize = 0;

            let childrens = if let Some(ref cs) = dir.childrens {
                cs
            } else {
                return Err(Error::new(ErrorKind::Other, "no child!"));
            };

            if offset >= childrens.len() as u64 {
                return Ok(());
            }

            let mut index: u64 = 0;
            for child in childrens {
                if index >= offset {
                    let name = match index {
                        0 => ".",
                        1 => "..",
                        _ => child.name.as_str(),
                    };

                    // make struct DireEntry and Entry
                    let st = child.stat64(ctx)?;
                    let dir_entry = DirEntry {
                        ino: st.st_ino,
                        offset: index + 1,
                        type_: entry_type_from_mode(st.st_mode) as u32,
                        name: name.as_bytes(),
                    };

                    let entry = Entry {
                        inode: child.inode,
                        generation: 0,
                        attr: st,
                        attr_flags: 0,
                        attr_timeout: self.config.attr_timeout,
                        entry_timeout: self.config.entry_timeout,
                    };

                    match add_entry(dir_entry, entry) {
                        Ok(0) => break,
                        Ok(l) => {
                            len += l;
                            if len as u32 >= size {
                                // no more space, stop here
                                return Ok(());
                            }
                        }

                        Err(e) => {
                            // when the buffer is still empty, return error, otherwise return the entry already added
                            if len == 0 {
                                return Err(e);
                            } else {
                                return Ok(());
                            }
                        }
                    }
                }

                index += 1;
            }
        }

        Ok(())
    }

    pub fn node_in_upper_layer(&self, node: Arc<OverlayInode>) -> Result<bool> {
        Ok(node.in_upper_layer())
    }

    pub fn create_node_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        // recursively going up and update hashmaps
        if self.node_in_upper_layer(Arc::clone(&node))? {
            return Ok(());
        }

        // not in upper layer, check parent
        let pnode = if let Some(n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(&n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        if self.node_in_upper_layer(Arc::clone(&pnode))? {
            // create directory here
            let upper = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());
            let layer = Arc::clone(upper.layer.as_ref().unwrap());
            let cname = utils::to_cstring(node.name.as_str())?;
            let st = node.stat64(ctx)?;
            let entry = layer.fs().mkdir(
                ctx,
                upper.inode.load(Ordering::Relaxed),
                cname.as_c_str(),
                st.st_mode,
                0,
            )?;

            // update node's first_layer
            let real_inode = Arc::new(RealInode {
                layer: Some(Arc::clone(&layer)),
                inode: AtomicU64::new(entry.inode),
                whiteout: AtomicBool::new(false),
                opaque: AtomicBool::new(false),
                hidden: AtomicBool::new(false),
                invalid: AtomicBool::new(false),
            });

            // what about st_ino/mode/dev..
            // FIXME: update st_ino/mode/dev, or query it from layer
            // on fly?
            *node.upper_inode.lock().unwrap() = Some(Arc::clone(&real_inode));

            return Ok(());
        } else {
            return self.create_node_directory(ctx, Arc::clone(&pnode));
        }
    }

    pub fn copy_symlink_up(
        &self,
        ctx: &Context,
        node: Arc<OverlayInode>,
    ) -> Result<Arc<OverlayInode>> {
        if self.node_in_upper_layer(Arc::clone(&node))? {
            return Ok(node);
        }

        let upper = self
            .upper_layer
            .as_ref()
            .map(|v| v.clone())
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        let st = node.stat64(ctx)?;

        let pnode = self.lookup_node(ctx, pnode.inode, "")?;

        assert!(pnode.in_upper_layer());
        assert!(st.st_mode & libc::S_IFMT == libc::S_IFLNK);
        let parent_real_inode = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());
        let node = self.lookup_node(ctx, pnode.inode, node.name.as_str())?;
        let rinode = &node.first_inode();
        let layer = Arc::clone(rinode.layer.as_ref().unwrap());

        // symlink
        // first inode, upper most layer inode
        let path = layer
            .fs()
            .readlink(ctx, rinode.inode.load(Ordering::Relaxed))?;
        let cpath = unsafe { CString::from_vec_unchecked(path) };
        let cname = utils::to_cstring(node.name.as_str())?;
        let entry = upper.fs().symlink(
            ctx,
            cpath.as_c_str(),
            parent_real_inode.inode.load(Ordering::Relaxed),
            cname.as_c_str(),
        )?;

        let real_inode = Arc::new(RealInode {
            layer: Some(upper),
            inode: AtomicU64::new(entry.inode),
            whiteout: AtomicBool::new(false),
            opaque: AtomicBool::new(false),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        // update first_inode() and upper_inode
        *node.upper_inode.lock().unwrap() = Some(Arc::clone(&real_inode));

        return Ok(Arc::clone(&node));
    }

    pub fn copy_regfile_up(
        &self,
        ctx: &Context,
        node: Arc<OverlayInode>,
    ) -> Result<Arc<OverlayInode>> {
        if self.node_in_upper_layer(Arc::clone(&node))? {
            return Ok(node);
        }
        let upper = self
            .upper_layer
            .as_ref()
            .map(|v| v.clone())
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        let st = node.stat64(ctx)?;

        let pnode = self.lookup_node(ctx, pnode.inode, "")?;

        assert!(pnode.in_upper_layer());
        assert!(st.st_mode & libc::S_IFMT != libc::S_IFLNK && !utils::is_dir(st));

        let parent_real_inode = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());
        let cname = utils::to_cstring(node.name.as_str())?;
        let node = self.lookup_node(ctx, pnode.inode, node.name.as_str())?;
        let rinode = &node.first_inode();
        let layer = Arc::clone(rinode.layer.as_ref().unwrap());

        // create the file in upper layer using information from lower layer

        let args = CreateIn {
            flags: 0,
            mode: st.st_mode,
            umask: 0,
            fuse_flags: 0,
        };

        let (entry, h, _) = upper.fs().create(
            ctx,
            parent_real_inode.inode.load(Ordering::Relaxed),
            cname.as_c_str(),
            args,
        )?;

        let real_inode = Arc::new(RealInode {
            layer: Some(Arc::clone(&upper)),
            inode: AtomicU64::new(entry.inode),
            whiteout: AtomicBool::new(false),
            opaque: AtomicBool::new(false),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        if h.is_none() {
            error!("no handle!!!");
            return Err(Error::new(ErrorKind::Other, "non handle!"));
        }

        let dst_handle = h.unwrap();

        let (h, _) = layer.fs().open(
            ctx,
            rinode.inode.load(Ordering::Relaxed),
            libc::O_RDONLY as u32,
            0,
        )?;

        if h.is_none() {
            error!("no handle!!!");
            return Err(Error::new(ErrorKind::Other, "non handle!"));
        }

        let src_handle = h.unwrap();

        // copy...
        // source: layer, rinode.inode, src_handle
        // dst: upper, real_inode.inode, dst_handle

        // need to impl ZeroCopyReader/ZeroCopyWriter, somehow like a pipe..
        // stupid: to create a temp file for now..
        // FIXME: need to copy xattr, futimes, set origin.TODO

        let template = utils::to_cstring("/tmp/fuse-overlay-XXXXXX")?;
        let template = template.into_raw();
        let flags = libc::O_RDWR | libc::O_CREAT;
        let fd = unsafe { libc::mkostemp(template, flags) };

        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut offset: usize = 0;
        let size = 4 * 1024 * 1024;
        loop {
            let ret = layer.fs().read(
                ctx,
                rinode.inode.load(Ordering::Relaxed),
                src_handle,
                &mut file,
                size,
                offset as u64,
                None,
                0,
            )?;
            if ret == 0 {
                break;
            }

            offset += ret;
        }

        file.seek(SeekFrom::Start(0))?;
        offset = 0;
        loop {
            let ret = upper.fs().write(
                ctx,
                entry.inode,
                dst_handle,
                &mut file,
                size,
                offset as u64,
                None,
                false,
                0,
                0,
            )?;
            if ret == 0 {
                break;
            }

            offset += ret;
        }

        drop(file);
        unsafe {
            libc::unlink(template);
        }

        // close handles
        layer.fs().release(
            ctx,
            rinode.inode.load(Ordering::Relaxed),
            0,
            src_handle,
            true,
            true,
            None,
        )?;
        upper
            .fs()
            .release(ctx, entry.inode, 0, dst_handle, true, true, None)?;

        // update upper_inode and first_inode()
        *node.upper_inode.lock().unwrap() = Some(Arc::clone(&real_inode));

        return Ok(Arc::clone(&node));
    }

    pub fn copy_node_up(
        &self,
        ctx: &Context,
        node: Arc<OverlayInode>,
    ) -> Result<Arc<OverlayInode>> {
        if self.node_in_upper_layer(Arc::clone(&node))? {
            return Ok(node);
        }
        // not in upper, copy it up
        let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        self.create_node_directory(ctx, Arc::clone(&pnode))?;
        // parent prepared
        let st = node.stat64(ctx)?;

        // directory
        if utils::is_dir(st) {
            self.create_node_directory(ctx, Arc::clone(&node))?;
            return Ok(Arc::clone(&node));
        }

        // other kind of files

        // symlink
        if st.st_mode * libc::S_IFMT == libc::S_IFLNK {
            return self.copy_symlink_up(ctx, Arc::clone(&node));
        }

        // reg file
        // need to use work directory and then rename file to
        // final destination for atomic reasons.. not deal with it for now,
        // use stupid copy at present. FIXME:
        // this need a lot of work here, ntimes, xattr, etc
        self.copy_regfile_up(ctx, Arc::clone(&node))
    }

    pub fn is_upper_layer(&self, l: Arc<Box<Layer>>) -> bool {
        l.is_upper()
    }

    pub fn do_rm(&self, ctx: &Context, parent: u64, name: &CStr, dir: bool) -> Result<()> {
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let pnode = self.lookup_node(ctx, parent, "")?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let sname = name.to_string_lossy().to_string();
        let node = self.lookup_node(ctx, parent, sname.as_str())?;
        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if dir {
            self.reload_directory(ctx, Arc::clone(&node))?;
            let (count, whiteouts, opaque) = node.count_entries_and_whiteout(ctx)?;
            trace!(
                "files: {}, whiteouts: {} opaque: {}\n",
                count,
                whiteouts,
                opaque
            );
            if count > 0 {
                return Err(Error::from_raw_os_error(libc::ENOTEMPTY));
            }

            // need to delete whiteouts?
            if whiteouts + opaque > 0 {
                if node.in_upper_layer() {
                    self.empty_node_directory(ctx, Arc::clone(&node))?;
                }
            }

            trace!("whiteouts deleted!\n");
        }

        let mut need_whiteout = true;
        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        if node.upper_layer_only() {
            need_whiteout = false;
        }

        // parent opaqued
        let real_pnode = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());
        let real_parent_inode = real_pnode.inode.load(Ordering::Relaxed);
        if real_pnode.opaque.load(Ordering::Relaxed) {
            need_whiteout = false;
        }

        let layer = Arc::clone(real_pnode.layer.as_ref().unwrap());

        if node.in_upper_layer() {
            if dir {
                layer.fs().rmdir(ctx, real_parent_inode, name)?;
            } else {
                layer.fs().unlink(ctx, real_parent_inode, name)?;
            }
        }

        trace!("toggling children and inodes hash\n");

        {
            pnode.childrens.lock().unwrap().remove(node.name.as_str());
            self.inodes.lock().unwrap().remove(&node.inode);
        }

        let sname = name.to_string_lossy().into_owned().to_owned();

        if need_whiteout {
            trace!("do_rm: creating whiteout\n");
            layer.create_whiteout(ctx, real_parent_inode, sname.as_str())?;
            pnode.loaded.store(false, Ordering::Relaxed);
            // readd whiteout node
            self.lookup_node(ctx, parent, sname.as_str())?;
            pnode.loaded.store(true, Ordering::Relaxed);
        }

        Ok(())
    }

    pub fn node_upper_layer_only(&self, node: Arc<OverlayInode>) -> bool {
        node.upper_layer_only()
    }

    pub fn empty_node_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        let st = node.stat64(ctx)?;
        if !utils::is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        self.reload_directory(ctx, Arc::clone(&node))?;
        if !node.in_upper_layer() {
            return Ok(());
        }

        // find the real inode
        let real_node = Arc::clone(node.upper_inode.lock().unwrap().as_ref().unwrap());
        let layer = Arc::clone(real_node.layer.as_ref().unwrap());
        let real_inode = real_node.inode.load(Ordering::Relaxed);

        // Copy node.childrens Hashmap to Vec, the Vec is also used as temp storage,
        // Without this, Rust won't allow us to remove them from node.childrens.
        let iter = node
            .childrens
            .lock()
            .unwrap()
            .iter()
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>();

        for child in iter {
            if child.in_upper_layer() {
                if child.whiteout.load(Ordering::Relaxed) {
                    layer.delete_whiteout(ctx, real_inode, child.name.as_str())?
                } else {
                    let s = child.stat64(ctx)?;
                    let cname = utils::to_cstring(&child.name)?;
                    if utils::is_dir(s) {
                        let (count, whiteouts, opaque) = child.count_entries_and_whiteout(ctx)?;
                        if count + whiteouts + opaque > 0 {
                            self.empty_node_directory(ctx, Arc::clone(&child))?;
                        }

                        layer.fs().rmdir(ctx, real_inode, cname.as_c_str())?
                    } else {
                        layer.fs().unlink(ctx, real_inode, cname.as_c_str())?;
                    }
                }

                {
                    // delete the child
                    self.inodes.lock().unwrap().remove(&child.inode);
                    node.childrens.lock().unwrap().remove(child.name.as_str());
                }
            }
        }

        Ok(())
    }

    pub fn delete_whiteout_node(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        if !node.whiteout.load(Ordering::Relaxed) {
            return Ok(());
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            return Ok(());
        }

        let _name = CString::new(node.name.as_str()).expect("invalid c string");
        let (layer, real_parent, pnode) = {
            let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
                Arc::clone(n)
            } else {
                return Err(Error::new(ErrorKind::Other, "no parent"));
            };

            let first_inode = pnode.first_inode();

            (
                Arc::clone(first_inode.layer.as_ref().unwrap()),
                first_inode.inode.load(Ordering::Relaxed),
                Arc::clone(&pnode),
            )
        };

        // delete white out and update hash
        layer.delete_whiteout(ctx, real_parent, node.name.as_str())?;
        self.inodes.lock().unwrap().remove(&node.inode);
        pnode.childrens.lock().unwrap().remove(node.name.as_str());

        Ok(())
    }

    pub fn find_real_info_from_handle(
        &self,
        _ctx: &Context,
        handle: Handle,
    ) -> Result<(Arc<Box<Layer>>, Inode, Handle)> {
        if let Some(h) = self.handles.lock().unwrap().get(&handle) {
            if let Some(ref rhd) = h.real_handle {
                let real_handle = rhd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&rhd.real_inode);
                let layer = Arc::clone(ri.layer.as_ref().unwrap());
                let real_inode = ri.inode.load(Ordering::Relaxed);
                return Ok((layer, real_inode, real_handle));
            }
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    pub fn find_real_inode(
        &self,
        _ctx: &Context,
        inode: Inode,
    ) -> Result<(Arc<Box<Layer>>, Inode)> {
        if let Some(n) = self.inodes.lock().unwrap().get(&inode) {
            let first = n.first_inode();
            let layer = Arc::clone(first.layer.as_ref().unwrap());
            let real_inode = first.inode.load(Ordering::Relaxed);

            return Ok((layer, real_inode));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }
}

impl ZeroCopyReader for File {
    fn read_to(
        &mut self,
        f: &mut dyn FileReadWriteVolatile,
        count: usize,
        off: u64,
    ) -> Result<usize> {
        let mut buf = Vec::<u8>::with_capacity(count);
        unsafe {
            buf.set_len(count);
        }
        let slice = unsafe { FileVolatileSlice::from_raw_ptr(buf.as_mut_ptr(), count) };

        let ret = f.read_at_volatile(slice, off)?;
        if ret > 0 {
            let slice = unsafe { FileVolatileSlice::from_raw_ptr(buf.as_mut_ptr(), ret) };
            f.write_volatile(slice)
        } else {
            Ok(0)
        }
    }
}

impl ZeroCopyWriter for File {
    fn write_from(
        &mut self,
        f: &mut dyn FileReadWriteVolatile,
        count: usize,
        off: u64,
    ) -> Result<usize> {
        let mut buf = Vec::<u8>::with_capacity(count);
        unsafe {
            buf.set_len(count);
        }
        let slice = unsafe { FileVolatileSlice::from_raw_ptr(buf.as_mut_ptr(), count) };
        let ret = f.read_at_volatile(slice, off)?;

        if ret > 0 {
            let slice = unsafe { FileVolatileSlice::from_raw_ptr(buf.as_mut_ptr(), ret) };
            self.write_volatile(slice)
        } else {
            Ok(0)
        }
    }

    fn available_bytes(&self) -> usize {
        0
    }
}
