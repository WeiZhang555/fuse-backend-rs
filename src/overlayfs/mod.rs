// Copyright (C) 2023 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
pub mod config;
pub mod sync_io;
mod utils;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Result, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::abi::fuse_abi::{ino64_t, stat64, statvfs64, CreateIn, ROOT_ID as FUSE_ROOT_ID};
use crate::api::filesystem::{
    Context, DirEntry, Entry, Layer, OpenOptions, ZeroCopyReader, ZeroCopyWriter,
};
#[cfg(not(feature = "async-io"))]
use crate::api::BackendFileSystem;
use crate::api::{SLASH_ASCII, VFS_MAX_INO};

use crate::common::file_buf::FileVolatileSlice;
use crate::common::file_traits::FileReadWriteVolatile;
use vmm_sys_util::tempfile::TempFile;

use self::config::Config;
use std::io::{Error, ErrorKind};

pub type Inode = u64;
pub type Handle = u64;
pub const OPAQUE_XATTR: &str = "user.fuseoverlayfs.opaque";
pub const UNPRIVILEGED_OPAQUE_XATTR: &str = "user.overlay.opaque";
pub const PRIVILEGED_OPAQUE_XATTR: &str = "trusted.overlay.opaque";
pub const MAXNAMELEN: usize = 256;
pub const CURRENT_DIR: &str = ".";
pub const PARENT_DIR: &str = "..";
pub const MAXBUFSIZE: usize = 1 << 20;

//type BoxedFileSystem = Box<dyn FileSystem<Inode = Inode, Handle = Handle> + Send + Sync>;
pub type BoxedLayer = Box<dyn Layer<Inode = Inode, Handle = Handle> + Send + Sync>;

// need real inode from layers, need inode to do layer
// operations
#[derive(Default)]
pub struct RealInode {
    // TODO: make this required field. @fangcun.zw
    pub layer: Option<Arc<BoxedLayer>>,
    pub in_upper_layer: bool,
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
    pub stat: Option<stat64>,
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
    pub st_ino: ino64_t,
    pub st_dev: libc::dev_t,
    pub mode: libc::mode_t,
    pub entry_type: u32,
    pub path: String,
    pub name: String,
    pub lookups: AtomicU64,
    pub hidden: AtomicBool,
    // Node is whiteout-ed.
    pub whiteout: AtomicBool,
    pub loaded: AtomicBool,
    // what about data source related data for each inode
    // put it into layer struct, ino -> private data hash
}

#[derive(Default)]
pub enum CachePolicy {
    Never,
    #[default]
    Auto,
    Always,
}
pub struct OverlayFs {
    // should be in daemon structure
    pub config: Config,
    pub lower_layers: Vec<Arc<BoxedLayer>>,
    pub upper_layer: Option<Arc<BoxedLayer>>,
    // inode management..
    pub root: Option<Arc<OverlayInode>>,
    pub inodes: Mutex<HashMap<u64, Arc<OverlayInode>>>,
    pub next_inode: AtomicU64,

    // manage opened fds.
    pub handles: Mutex<HashMap<u64, Arc<HandleData>>>,
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
    // Invalid handle.
    pub invalid: AtomicBool,
}

pub struct HandleData {
    pub node: Arc<OverlayInode>,
    //    pub childrens: Option<Vec<Arc<OverlayInode>>>,
    pub offset: libc::off_t,

    // others?
    pub real_handle: Option<RealHandle>,
}

impl RealInode {
    pub fn stat64_ignore_enoent(&self, ctx: &Context) -> Result<Option<stat64>> {
        if self.invalid.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let layer = self.layer.as_ref();
        match layer
            .ok_or(Error::from_raw_os_error(libc::EINVAL))?
            .getattr(ctx, self.inode.load(Ordering::Relaxed), None)
        {
            Ok((v1, _v2)) => Ok(Some(v1)),

            Err(e) => match e.raw_os_error() {
                Some(raw_error) => {
                    if raw_error != libc::ENOENT
                        && raw_error != libc::ENOTDIR
                        && raw_error != libc::ENAMETOOLONG
                    {
                        return Ok(None);
                    }
                    Err(e)
                }
                None => Err(e),
            },
        }
    }

    // file exists, returns true, not exists return false
    // otherwise, error out
    // Ok(None) denotes no entry
    pub(crate) fn lookup_child_ignore_enoent(
        &self,
        ctx: &Context,
        name: &str,
    ) -> Result<Option<Entry>> {
        let cname = CString::new(name).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        // Real inode must have a layer.
        let layer = self
            .layer
            .as_ref()
            .ok_or(Error::from_raw_os_error(libc::EINVAL))?;

        match layer.lookup(ctx, self.inode.load(Ordering::Relaxed), cname.as_c_str()) {
            Ok(v) => {
                // Negative entry also indicates missing entry.
                if v.inode == 0 {
                    return Ok(None);
                }
                Ok(Some(v))
            }
            Err(e) => {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::ENOENT || raw_error == libc::ENAMETOOLONG {
                        return Ok(None);
                    }
                }

                Err(e)
            }
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
                // TODO: change to 0?? @weizhang555.zw
                inode,
                whiteout,
                opaque: false,
                stat: None,
            }));
        }

        // Find child Entry with <name> under directory with inode <self.inode>.
        match self.lookup_child_ignore_enoent(ctx, name)? {
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
                    opaque: layer.is_opaque(ctx, v.inode)?,
                    stat: Some(v.attr),
                }))
            }
            None => Ok(None),
        }
    }
}

impl OverlayInode {
    pub fn new() -> Self {
        OverlayInode::default()
    }

    pub fn stat64(&self, ctx: &Context) -> Result<stat64> {
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

    pub fn count_entries_and_whiteout(&self, ctx: &Context) -> Result<(u64, u64)> {
        let mut count = 0;
        let mut whiteouts = 0;

        let st = self.stat64(ctx)?;

        // must be directory
        if !utils::is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        for (_, child) in self.childrens.lock().unwrap().iter() {
            if child.whiteout.load(Ordering::Relaxed) {
                whiteouts += 1;
            } else {
                count += 1;
            }
        }

        Ok((count, whiteouts))
    }

    pub fn open(
        &self,
        ctx: &Context,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<(Arc<BoxedLayer>, Option<Handle>, OpenOptions)> {
        let ri = &self.first_inode();
        if let Some(ref l) = ri.layer {
            let (h, o, _) = l.open(ctx, ri.inode.load(Ordering::Relaxed), flags, fuse_flags)?;
            Ok((Arc::clone(l), h, o))
        } else {
            Err(Error::new(ErrorKind::Other, "no first layer"))
        }
    }

    pub fn in_upper_layer(&self) -> bool {
        self.upper_inode.lock().unwrap().is_some()
    }

    pub fn upper_layer_only(&self) -> bool {
        self.lower_inodes.is_empty()
    }

    pub fn first_inode(&self) -> Arc<RealInode> {
        // It must have either upper inode or one lower inode.
        match self.upper_inode.lock().unwrap().as_ref() {
            Some(v) => Arc::clone(v),
            None => Arc::clone(&self.lower_inodes[0]),
        }
    }

    pub fn upper_inode_with_layer(&self) -> Option<(Arc<RealInode>, Arc<BoxedLayer>)> {
        match self.upper_inode.lock().unwrap().as_ref() {
            Some(v) => match v.layer.as_ref().ok_or_else(|| {
                // No layer indicates an internal bug.
                error!(
                    "BUG: no layer for inode {}",
                    v.inode.load(Ordering::Relaxed)
                );
                Error::from_raw_os_error(libc::EINVAL)
            }) {
                Ok(l) => Some((Arc::clone(v), Arc::clone(l))),
                Err(_) => None,
            },
            None => None,
        }
    }

    pub fn childrens(&self) -> HashMap<String, Arc<OverlayInode>> {
        self.childrens.lock().unwrap().clone()
    }
}

fn entry_type_from_mode(mode: libc::mode_t) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFBLK => libc::DT_BLK,
        libc::S_IFCHR => libc::DT_CHR,
        libc::S_IFDIR => libc::DT_DIR,
        libc::S_IFIFO => libc::DT_FIFO,
        libc::S_IFLNK => libc::DT_LNK,
        libc::S_IFREG => libc::DT_REG,
        libc::S_IFSOCK => libc::DT_SOCK,
        _ => libc::DT_UNKNOWN,
    }
}

impl OverlayFs {
    pub fn new(
        upper: Option<Arc<BoxedLayer>>,
        lowers: Vec<Arc<BoxedLayer>>,
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

    pub fn root_inode(&self) -> Inode {
        FUSE_ROOT_ID
    }

    pub fn init_root(&mut self) -> Result<()> {
        let mut root = OverlayInode::new();
        root.inode = FUSE_ROOT_ID;
        root.path = String::from("");
        root.name = String::from("");
        root.entry_type = libc::DT_DIR as u32;
        root.lookups = AtomicU64::new(2);
        let ctx = Context::default();

        // Update upper inode
        if let Some(layer) = self.upper_layer.as_ref() {
            let ino = layer.root_inode();
            let real = Arc::new(RealInode {
                layer: Some(Arc::clone(layer)),
                in_upper_layer: true,
                inode: AtomicU64::new(ino),
                whiteout: AtomicBool::new(false),
                opaque: AtomicBool::new(false),
                hidden: AtomicBool::new(false),
                invalid: AtomicBool::new(false),
            });
            root.upper_inode = Mutex::new(Some(real.clone()));
        }

        // Update lower inodes.
        for layer in self.lower_layers.iter() {
            let ino = layer.root_inode();
            let opaque = layer.is_opaque(&ctx, ino)?;
            let real = RealInode {
                layer: Some(Arc::clone(layer)),
                in_upper_layer: false,
                inode: AtomicU64::new(ino),
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
        self.inode_add(root_node.inode, Arc::clone(&root_node));

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
        layer: Arc<BoxedLayer>,
        is_upper_layer: bool,
    ) -> Result<OverlayInode> {
        let mut new = OverlayInode::new();
        new.whiteout.store(ris.whiteout, Ordering::Relaxed);
        let real_inode = Arc::new(RealInode {
            layer: Some(Arc::clone(&layer)),
            in_upper_layer: is_upper_layer,
            inode: AtomicU64::new(ris.inode),
            whiteout: AtomicBool::new(ris.whiteout),
            opaque: AtomicBool::new(ris.opaque),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        new.lookups = AtomicU64::new(1);
        if is_upper_layer {
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
        self.inodes.lock().unwrap().get(&inode).cloned()
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
        if name.contains([SLASH_ASCII as char]) {
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
                new = self.make_overlay_inode(
                    &ris,
                    Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                        error!("no layer for inode {}", ris.inode);
                        Error::from_raw_os_error(libc::EINVAL)
                    })?),
                    true,
                )?;
            }
        }

        'layer_loop: for ri in &pnode.lower_inodes {
            // Find an entry.
            if let Some(ris) = ri.lookup_node(ctx, name)? {
                let layer = Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                    error!("no layer for inode {}", ris.inode);
                    Error::from_raw_os_error(libc::EINVAL)
                })?);
                let real_inode = Arc::new(RealInode {
                    layer: Some(Arc::clone(&layer)),
                    in_upper_layer: false,
                    inode: AtomicU64::new(ris.inode),
                    whiteout: AtomicBool::new(ris.whiteout),
                    hidden: AtomicBool::new(false),
                    opaque: AtomicBool::new(ris.opaque),
                    invalid: AtomicBool::new(false),
                });

                // TODO: not sure if this part is correct。  @weizhang555.zw
                if !node_inited {
                    node_inited = true;
                    new = self.make_overlay_inode(&ris, Arc::clone(&layer), false)?;
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
            self.inode_add(new_node.inode, Arc::clone(&new_node));
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
            Ok(n) => Ok(Some(Arc::clone(&n))),
            Err(e) => {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::ENOENT {
                        return Ok(None);
                    }
                }
                Err(e)
            }
        }
    }

    pub fn get_node_from_inode(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        if let Some(v) = self.inode_get(inode) {
            return Some(v);
        }

        None
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
            let l = Arc::clone(real.layer.as_ref().ok_or_else(|| {
                error!("no layer for inode {}", real.inode.load(Ordering::Relaxed));
                Error::from_raw_os_error(libc::EINVAL)
            })?);
            let rinode = real.inode.load(Ordering::Relaxed);

            // Open the directory and load each entry.
            let opendir_res = l.opendir(ctx, rinode, libc::O_RDONLY as u32);
            let handle = match opendir_res {
                Ok((handle, _)) => match handle {
                    Some(h) => h,
                    _ => 0,
                },
                // opendir may not be supported if no_opendir is set, so we can ignore this error.
                Err(e) => {
                    match e.raw_os_error() {
                        Some(raw_error) => {
                            if raw_error == libc::ENOSYS {
                                // We can still call readdir if opendir is not supported in some layer.
                                0
                            } else {
                                return Err(e);
                            }
                        }
                        None => {
                            return Err(e);
                        }
                    }
                }
            };

            let mut more = true;
            let mut offset = 0;
            let bufsize = 1024;
            while more {
                more = false;
                l.readdir(
                    ctx,
                    rinode,
                    handle,
                    bufsize,
                    offset,
                    &mut |d| -> Result<usize> {
                        more = true;
                        offset = d.offset;
                        let child_name = String::from_utf8_lossy(d.name).into_owned();

                        trace!("entry: {}", child_name.as_str());

                        if child_name.eq(CURRENT_DIR) || child_name.eq(PARENT_DIR) {
                            return Ok(1);
                        }

                        if let Err(e) = self.lookup_node(ctx, ovl_inode, child_name.as_str()) {
                            error!(
                                "lookup node name {} under parent {} failed: {}",
                                child_name.as_str(),
                                ovl_inode,
                                e
                            );
                        }

                        Ok(1)
                    },
                )?;
            }

            if handle > 0 {
                if let Err(e) = l.releasedir(ctx, rinode, libc::O_RDONLY as u32, handle) {
                    // ignore ENOSYS
                    match e.raw_os_error() {
                        Some(raw_error) => {
                            if raw_error != libc::ENOSYS {
                                return Err(e);
                            }
                        }
                        None => {
                            return Err(e);
                        }
                    }
                }
            }
        } else {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        Ok(())
    }

    pub fn load_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        let tmp_ui = node.upper_inode.lock().unwrap().as_ref().cloned();

        if let Some(ref ui) = tmp_ui {
            debug!("load upper for '{}'", node.path.as_str());
            // upper layer
            if ui.whiteout.load(Ordering::Relaxed) || ui.invalid.load(Ordering::Relaxed) {
                debug!("directory is whiteout or invalid");
                return Ok(());
            }

            if let Some(st) = ui.stat64_ignore_enoent(ctx)? {
                if !utils::is_dir(st) {
                    debug!("{} is not a directory", node.path.as_str());
                    // not directory
                    return Ok(());
                }

                // process this layer
                self.load_directory_layer(ctx, node.inode, Arc::clone(ui))?;
            }

            // if opaque, stop here
            if ui.opaque.load(Ordering::Relaxed) {
                node.loaded.store(true, Ordering::Relaxed);
                debug!("directory {} is opaque", node.path.as_str());
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
                    debug!("{} is not a directory", node.path.as_str());
                    // not directory
                    break 'layer_loop;
                }

                // process this layer
                if let Err(e) = self.load_directory_layer(ctx, node.inode, Arc::clone(ri)) {
                    if let Some(raw_error) = e.raw_os_error() {
                        if raw_error == libc::ENOENT {
                            continue 'layer_loop;
                        }
                    }

                    return Err(e);
                }
            }

            // if opaque, stop here
            if ri.opaque.load(Ordering::Relaxed) {
                debug!("directory {} is opaque", node.path.as_str());
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

    pub fn get_first_lower_layer(&self) -> Option<Arc<BoxedLayer>> {
        if !self.lower_layers.is_empty() {
            Some(Arc::clone(&self.lower_layers[0]))
        } else {
            None
        }
    }

    pub fn get_first_layer(&self) -> Option<Arc<BoxedLayer>> {
        if let Some(ref l) = self.upper_layer {
            return Some(Arc::clone(l));
        }

        self.get_first_lower_layer()
    }

    pub fn forget_one(&self, inode: Inode, count: u64) {
        if inode == self.root_inode() || inode == 0 {
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
        let mut lookups = v.lookups.load(Ordering::Relaxed);

        if lookups < count {
            lookups = 0;
        } else {
            lookups -= count;
        }
        v.lookups.store(lookups, Ordering::Relaxed);

        if lookups == 0 {
            debug!("inode is forgotten: {}, name {}", inode, v.name);
            let _ = self.inode_remove(inode);
            let parent = v.parent.lock().unwrap();

            if let Some(p) = parent.upgrade() {
                // remove it from hashmap
                p.childrens.lock().unwrap().remove(v.name.as_str());
                p.loaded.store(true, Ordering::Relaxed);
            }
        }

        // FIXME: is it possible that the inode still in childrens map?
    }

    pub fn do_lookup(&self, ctx: &Context, parent: Inode, name: &str) -> Result<Entry> {
        let node = self.lookup_node(ctx, parent, name)?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if self.get_node_from_inode(parent).is_none() {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        };

        let st = node.stat64(ctx)?;

        // load this directory here
        if utils::is_dir(st) {
            self.load_directory(ctx, Arc::clone(&node))?;
            node.loaded.store(true, Ordering::Relaxed);
        }

        // FIXME: can forget happen between found and increase reference counter?
        node.lookups.fetch_add(1, Ordering::Relaxed);

        Ok(Entry {
            inode: node.inode,
            generation: 0,
            attr: st,
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    pub fn do_statvfs(&self, ctx: &Context, inode: Inode) -> Result<statvfs64> {
        match self.inode_get(inode) {
            Some(ovl) => {
                // Find upper layer.
                let real_inode = ovl
                    .upper_inode
                    .lock()
                    .unwrap()
                    .as_ref()
                    .cloned()
                    .or_else(|| {
                        if !ovl.lower_inodes.is_empty() {
                            Some(Arc::clone(&ovl.lower_inodes[0]))
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| Error::new(ErrorKind::Other, "backend inode not found"))?;
                let layer = real_inode.layer.as_ref().ok_or_else(|| {
                    Error::new(ErrorKind::Other, "layer not found for real inode")
                })?;
                layer.statfs(ctx, real_inode.inode.load(Ordering::Relaxed))
            }
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    pub fn get_fs_namemax(&self, ctx: &Context) -> u64 {
        match self.do_statvfs(ctx, self.root_inode()) {
            Ok(sfs) => sfs.f_namemax,
            Err(_) => 255,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn do_readdir(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: u64,
        size: u32,
        offset: u64,
        is_readdirplus: bool,
        add_entry: &mut dyn FnMut(DirEntry, Option<Entry>) -> Result<usize>,
    ) -> Result<()> {
        trace!(
            "do_readir: handle: {}, size: {}, offset: {}",
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
        let ovl_inode = match self.handles.lock().unwrap().get(&handle) {
            Some(dir) => dir.node.clone(),
            None => {
                // Try to get data with inode.
                let node = self.lookup_node(ctx, inode, ".")?;

                if node.whiteout.load(Ordering::Relaxed) {
                    return Err(Error::from_raw_os_error(libc::ENOENT));
                }

                let st = node.stat64(ctx)?;
                if !utils::is_dir(st) {
                    return Err(Error::from_raw_os_error(libc::ENOTDIR));
                }

                // Reload directory if it had not been loaded.
                self.reload_directory(ctx, Arc::clone(&node))?;

                node.clone()
            }
        };

        let mut childrens = Vec::new();
        //add myself as "."
        childrens.push((".".to_string(), ovl_inode.clone()));

        //add parent
        let parent_node = match ovl_inode.parent.lock().unwrap().upgrade() {
            Some(p) => p.clone(),
            None => Arc::clone(self.root.as_ref().ok_or_else(|| {
                error!("do_readdir: root is none");
                Error::from_raw_os_error(libc::ENOENT)
            })?),
        };
        childrens.push(("..".to_string(), parent_node));

        for (_, child) in ovl_inode.childrens.lock().unwrap().iter() {
            // skip whiteout node
            if child.whiteout.load(Ordering::Relaxed) || child.hidden.load(Ordering::Relaxed) {
                continue;
            }
            childrens.push((child.name.clone(), child.clone()));
        }

        let mut len: usize = 0;
        if offset >= childrens.len() as u64 {
            return Ok(());
        }

        for (index, (name, child)) in (0_u64..).zip(childrens.into_iter()) {
            if index >= offset {
                // make struct DireEntry and Entry
                let st = child.stat64(ctx)?;
                let dir_entry = DirEntry {
                    ino: st.st_ino,
                    offset: index + 1,
                    type_: entry_type_from_mode(st.st_mode) as u32,
                    name: name.as_bytes(),
                };

                let entry = if is_readdirplus {
                    child.lookups.fetch_add(1, Ordering::Relaxed);
                    Some(Entry {
                        inode: child.inode,
                        generation: 0,
                        attr: st,
                        attr_flags: 0,
                        attr_timeout: self.config.attr_timeout,
                        entry_timeout: self.config.entry_timeout,
                    })
                } else {
                    None
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
            let upper =
                Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                    error!("no upper inode for {}", pnode.inode);
                    Error::from_raw_os_error(libc::EINVAL)
                })?);
            let layer = Arc::clone(upper.layer.as_ref().ok_or_else(|| {
                error!("no layer for inode {}", upper.inode.load(Ordering::Relaxed));
                Error::from_raw_os_error(libc::EINVAL)
            })?);
            let cname = utils::to_cstring(node.name.as_str())?;
            let st = node.stat64(ctx)?;
            let entry = layer.mkdir(
                ctx,
                upper.inode.load(Ordering::Relaxed),
                cname.as_c_str(),
                st.st_mode,
                0,
            )?;

            // update node's first_layer
            let real_inode = Arc::new(RealInode {
                layer: Some(Arc::clone(&layer)),
                in_upper_layer: true,
                inode: AtomicU64::new(entry.inode),
                whiteout: AtomicBool::new(false),
                opaque: AtomicBool::new(false),
                hidden: AtomicBool::new(false),
                invalid: AtomicBool::new(false),
            });

            // what about st_ino/mode/dev..
            // FIXME: update st_ino/mode/dev, or query it from layer
            // on fly?
            node.upper_inode
                .lock()
                .unwrap()
                .replace(Arc::clone(&real_inode));

            Ok(())
        } else {
            self.create_node_directory(ctx, Arc::clone(&pnode))
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
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        let pnode = self.lookup_node(ctx, pnode.inode, "")?;

        let parent_real_inode = Arc::clone(
            pnode
                .upper_inode
                .lock()
                .unwrap()
                .as_ref()
                .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?,
        );
        let node = self.lookup_node(ctx, pnode.inode, node.name.as_str())?;
        let rinode = &node.first_inode();
        let layer = Arc::clone(
            rinode
                .layer
                .as_ref()
                .ok_or_else(|| Error::from_raw_os_error(libc::EINVAL))?,
        );

        // symlink
        // first inode, upper most layer inode
        let path = layer.readlink(ctx, rinode.inode.load(Ordering::Relaxed))?;
        let cpath = unsafe { CString::from_vec_unchecked(path) };
        let cname = utils::to_cstring(node.name.as_str())?;
        let entry = upper.symlink(
            ctx,
            cpath.as_c_str(),
            parent_real_inode.inode.load(Ordering::Relaxed),
            cname.as_c_str(),
        )?;

        let real_inode = Arc::new(RealInode {
            layer: Some(upper),
            in_upper_layer: rinode.in_upper_layer,
            inode: AtomicU64::new(entry.inode),
            whiteout: AtomicBool::new(false),
            opaque: AtomicBool::new(false),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        // update first_inode() and upper_inode
        *node.upper_inode.lock().unwrap() = Some(Arc::clone(&real_inode));

        Ok(Arc::clone(&node))
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
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        let st = node.stat64(ctx)?;

        let pnode = self.lookup_node(ctx, pnode.inode, "")?;

        //assert!(pnode.in_upper_layer());
        //assert!(st.st_mode & libc::S_IFMT != libc::S_IFLNK && !utils::is_dir(st));

        let parent_real_inode =
            Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                error!("parent {} has no upper inode", pnode.inode);
                Error::from_raw_os_error(libc::EINVAL)
            })?);
        let cname = utils::to_cstring(node.name.as_str())?;
        let node = self.lookup_node(ctx, pnode.inode, node.name.as_str())?;
        let rinode = &node.first_inode();
        let layer = Arc::clone(rinode.layer.as_ref().ok_or_else(|| {
            error!("node {} has no layer", node.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?);

        // create the file in upper layer using information from lower layer

        let args = CreateIn {
            flags: 0,
            mode: st.st_mode,
            umask: 0,
            fuse_flags: 0,
        };

        let (entry, h, _, _) = upper.create(
            ctx,
            parent_real_inode.inode.load(Ordering::Relaxed),
            cname.as_c_str(),
            args,
        )?;

        let real_inode = Arc::new(RealInode {
            layer: Some(Arc::clone(&upper)),
            in_upper_layer: true,
            inode: AtomicU64::new(entry.inode),
            whiteout: AtomicBool::new(false),
            opaque: AtomicBool::new(false),
            hidden: AtomicBool::new(false),
            invalid: AtomicBool::new(false),
        });

        let dst_handle = h.ok_or_else(|| {
            error!("no handle!!!");
            Error::new(ErrorKind::Other, "non handle!")
        })?;

        let (h, _, _) = layer.open(
            ctx,
            rinode.inode.load(Ordering::Relaxed),
            libc::O_RDONLY as u32,
            0,
        )?;

        let src_handle = h.ok_or_else(|| {
            error!("no handle!!!");
            Error::new(ErrorKind::Other, "non handle!")
        })?;

        // copy...
        // source: layer, rinode.inode, src_handle
        // dst: upper, real_inode.inode, dst_handle

        // need to impl ZeroCopyReader/ZeroCopyWriter, somehow like a pipe..
        // stupid: to create a temp file for now..
        // FIXME: need to copy xattr, futimes, set origin.TODO
        // FIXME: use workdir as temporary storage instead of local tmpfs.

        // let template = utils::to_cstring("/tmp/fuse-overlay-XXXXXX")?;
        // let template = template.into_raw();
        // let flags = libc::O_RDWR | libc::O_CREAT;
        // let fd = unsafe { libc::mkostemp(template, flags) };

        // if fd < 0 {
        //     return Err(Error::last_os_error());
        // }
        //let mut file = unsafe { File::from_raw_fd(fd) };

        let mut file = TempFile::new().unwrap().into_file();
        let mut offset: usize = 0;
        let size = 4 * 1024 * 1024;
        loop {
            let ret = layer.read(
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
            let ret = upper.write(
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
        // unsafe {
        //     libc::unlink(template);
        // }

        // close handles
        layer.release(
            ctx,
            rinode.inode.load(Ordering::Relaxed),
            0,
            src_handle,
            true,
            true,
            None,
        )?;
        upper.release(ctx, entry.inode, 0, dst_handle, true, true, None)?;

        // update upper_inode and first_inode()
        *node.upper_inode.lock().unwrap() = Some(Arc::clone(&real_inode));

        Ok(Arc::clone(&node))
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

    pub fn do_rm(&self, ctx: &Context, parent: u64, name: &CStr, dir: bool) -> Result<()> {
        // FIXME: should we defer removal after lookup count decreased to zero? @fangcun.zw
        if self.upper_layer.is_none() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // Find parent Overlay Inode.
        let pnode = self.lookup_node(ctx, parent, "")?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // Find the Overlay Inode for child with <name>.
        let sname = name.to_string_lossy().to_string();
        let node = self.lookup_node(ctx, parent, sname.as_str())?;
        if node.whiteout.load(Ordering::Relaxed) {
            // already deleted.
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if dir {
            self.reload_directory(ctx, Arc::clone(&node))?;
            let (count, whiteouts) = node.count_entries_and_whiteout(ctx)?;
            trace!("files: {}, whiteouts: {}\n", count, whiteouts);
            if count > 0 {
                return Err(Error::from_raw_os_error(libc::ENOTEMPTY));
            }

            // need to delete whiteouts?
            if whiteouts > 0 && node.in_upper_layer() {
                self.empty_node_directory(ctx, Arc::clone(&node))?;
            }

            trace!("whiteouts deleted!\n");
        }

        let mut need_whiteout = true;
        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        if node.upper_layer_only() {
            need_whiteout = false;
        }

        // parent opaqued
        let real_pnode =
            Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                error!("parent {} has no upper inode", pnode.inode);
                Error::from_raw_os_error(libc::EINVAL)
            })?);
        let real_parent_inode = real_pnode.inode.load(Ordering::Relaxed);
        if real_pnode.opaque.load(Ordering::Relaxed) {
            need_whiteout = false;
        }

        let layer = Arc::clone(real_pnode.layer.as_ref().ok_or_else(|| {
            error!("parent {} has no layer", pnode.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?);

        if node.in_upper_layer() {
            if dir {
                layer.rmdir(ctx, real_parent_inode, name)?;
            } else {
                layer.unlink(ctx, real_parent_inode, name)?;
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
            layer.create_whiteout(ctx, real_parent_inode, name)?;
            pnode.loaded.store(false, Ordering::Relaxed);
            // readd whiteout node
            self.lookup_node(ctx, parent, sname.as_str())?;
            pnode.loaded.store(true, Ordering::Relaxed);
        }

        Ok(())
    }

    fn do_fsync(
        &self,
        ctx: &Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
        syncdir: bool,
    ) -> Result<()> {
        // Use O_RDONLY flags which indicates no copy up.
        let data = self.get_data(ctx, Some(handle), inode, libc::O_RDONLY as u32)?;

        match data.real_handle {
            // FIXME: need to test if inode matches corresponding handle?
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
            Some(ref rhd) => {
                let real_handle = rhd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&rhd.real_inode);
                let layer = Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                    error!(
                        "real inode {} has no layer",
                        ri.inode.load(Ordering::Relaxed)
                    );
                    Error::from_raw_os_error(libc::EINVAL)
                })?);

                if !ri.in_upper_layer {
                    // TODO: in lower layer, error out or just success?
                    return Err(Error::from_raw_os_error(libc::EROFS));
                }
                let real_inode = ri.inode.load(Ordering::Relaxed);
                if syncdir {
                    layer.fsyncdir(ctx, real_inode, datasync, real_handle)
                } else {
                    layer.fsync(ctx, real_inode, datasync, real_handle)
                }
            }
        }
    }

    pub fn node_upper_layer_only(&self, node: Arc<OverlayInode>) -> bool {
        node.upper_layer_only()
    }

    // Delete everything in the directory only on upper layer, ignore lower layers.
    pub fn empty_node_directory(&self, ctx: &Context, node: Arc<OverlayInode>) -> Result<()> {
        let st = node.stat64(ctx)?;
        if !utils::is_dir(st) {
            // This function can only be called on directories.
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        self.reload_directory(ctx, Arc::clone(&node))?;
        if !node.in_upper_layer() {
            return Ok(());
        }

        // find the real inode
        let real_node = Arc::clone(node.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
            error!("node {} has no upper inode", node.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?);
        let layer = Arc::clone(real_node.layer.as_ref().ok_or_else(|| {
            error!("node {} has no layer", node.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?);
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
            // Only care about upper layer, ignore lower layers.
            if child.in_upper_layer() {
                if child.whiteout.load(Ordering::Relaxed) {
                    layer.delete_whiteout(
                        ctx,
                        real_inode,
                        utils::to_cstring(child.name.as_str())?.as_c_str(),
                    )?
                } else {
                    let s = child.stat64(ctx)?;
                    let cname = utils::to_cstring(&child.name)?;
                    if utils::is_dir(s) {
                        let (count, whiteouts) = child.count_entries_and_whiteout(ctx)?;
                        if count + whiteouts > 0 {
                            self.empty_node_directory(ctx, Arc::clone(&child))?;
                        }

                        layer.rmdir(ctx, real_inode, cname.as_c_str())?
                    } else {
                        layer.unlink(ctx, real_inode, cname.as_c_str())?;
                    }
                }

                // Keep "{}" for dropping lock.
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
                Arc::clone(first_inode.layer.as_ref().ok_or_else(|| {
                    error!("parent {} has no layer", pnode.inode);
                    Error::from_raw_os_error(libc::EINVAL)
                })?),
                first_inode.inode.load(Ordering::Relaxed),
                Arc::clone(&pnode),
            )
        };

        // delete white out and update hash
        layer.delete_whiteout(
            ctx,
            real_parent,
            utils::to_cstring(node.name.as_str())?.as_c_str(),
        )?;
        self.inodes.lock().unwrap().remove(&node.inode);
        pnode.childrens.lock().unwrap().remove(node.name.as_str());

        Ok(())
    }

    pub fn find_real_info_from_handle(
        &self,
        _ctx: &Context,
        handle: Handle,
    ) -> Result<(Arc<BoxedLayer>, Inode, Handle)> {
        if let Some(h) = self.handles.lock().unwrap().get(&handle) {
            if let Some(ref rhd) = h.real_handle {
                let real_handle = rhd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&rhd.real_inode);
                let layer = Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                    error!(
                        "real inode {} has no layer",
                        ri.inode.load(Ordering::Relaxed)
                    );
                    Error::from_raw_os_error(libc::EINVAL)
                })?);
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
    ) -> Result<(Arc<BoxedLayer>, Inode)> {
        if let Some(n) = self.inodes.lock().unwrap().get(&inode) {
            let first = n.first_inode();
            let layer = Arc::clone(first.layer.as_ref().ok_or_else(|| {
                error!(
                    "real inode {} has no layer",
                    first.inode.load(Ordering::Relaxed)
                );
                Error::from_raw_os_error(libc::EINVAL)
            })?);
            let real_inode = first.inode.load(Ordering::Relaxed);

            return Ok((layer, real_inode));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    pub fn get_data(
        &self,
        ctx: &Context,
        handle: Option<Handle>,
        inode: Inode,
        flags: u32,
    ) -> Result<Arc<HandleData>> {
        let no_open = self.no_open.load(Ordering::Relaxed);
        if !no_open {
            if let Some(h) = handle {
                if let Some(v) = self.handles.lock().unwrap().get(&h) {
                    if v.node.inode == inode {
                        return Ok(Arc::clone(v));
                    }
                }
            }
        } else {
            let readonly: bool = flags
                & (libc::O_APPEND | libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_WRONLY)
                    as u32
                == 0;

            // lookup node
            let node = self.lookup_node(ctx, inode, "")?;

            // whiteout node
            if node.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::ENOENT));
            }

            if !readonly {
                // Check if upper layer exists, return EROFS is not exists.
                self.upper_layer
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;
                // copy up to upper layer
                self.copy_node_up(ctx, Arc::clone(&node))?;
            }

            // assign a handle in overlayfs and open it
            //let (_l, h, _) = node.open(ctx, flags as u32, fuse_flags)?;
            //if let Some(handle) = h {
            //let hd = self.next_handle.fetch_add(1, Ordering::Relaxed);
            let handle_data = HandleData {
                node: Arc::clone(&node),
                offset: 0,
                real_handle: Some(RealHandle {
                    real_inode: node.first_inode(),
                    handle: AtomicU64::new(0),
                    invalid: AtomicBool::new(true),
                }),
            };
            return Ok(Arc::new(handle_data));
            //}
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
        let mut buf = vec![0_u8; count];
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
        let mut buf = vec![0_u8; count];
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

#[cfg(not(feature = "async-io"))]
impl BackendFileSystem for OverlayFs {
    /// mount returns the backend file system root inode entry and
    /// the largest inode number it has.
    fn mount(&self) -> Result<(Entry, u64)> {
        let ctx = Context::default();
        let entry = self.do_lookup(&ctx, self.root_inode(), "")?;
        Ok((entry, VFS_MAX_INO))
    }

    /// Provides a reference to the Any trait. This is useful to let
    /// the caller have access to the underlying type behind the
    /// trait.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
