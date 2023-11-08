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

// RealInode represents one inode object in specific layer.
// Also, each RealInode maps to one Entry, which should be 'forgotten' after drop.
pub struct RealInode {
    pub layer: Arc<BoxedLayer>,
    pub in_upper_layer: bool,
    pub inode: u64,
    // File is whiteouted, we need to hide it.
    pub whiteout: bool,
    // Directory is opaque, we need to hide all entries inside it.
    pub opaque: bool,
    pub stat: Option<stat64>,
}

// #[derive(Default, Debug)]
// pub struct RealInodeStats {
//     pub inode: u64,
//     pub whiteout: bool,
//     pub opaque: bool,
//     pub stat: Option<stat64>,
// }

#[derive(Default)]
pub struct OverlayInode {
    // Inode hash table, map from 'name' to 'OverlayInode'.
    pub childrens: Mutex<HashMap<String, Arc<OverlayInode>>>,
    pub parent: Mutex<Weak<OverlayInode>>,
    // Backend inodes from all low layers.
    pub lower_inodes: Vec<RealInode>,
    // Backend inode from upper layer.
    pub upper_inode: Mutex<Option<RealInode>>,
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
    // Active inodes.
    pub inodes: Mutex<HashMap<u64, Arc<OverlayInode>>>,
    // Deleted inodes are unlinked inodes with non zero lookup count.
    pub deleted_inodes: Mutex<HashMap<u64, Arc<OverlayInode>>>,
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
    pub layer: Arc<BoxedLayer>,
    pub in_upper_layer: bool,
    pub inode: u64,
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

// RealInode is a wrapper of one inode in specific layer.
// All layer operations returning Entry should be done in RealInode implementation
// so that we can record the refcount(lookup count) of each inode.
impl RealInode {
    pub(crate) fn new(
        layer: Arc<BoxedLayer>,
        in_upper_layer: bool,
        inode: u64,
        whiteout: bool,
        opaque: bool,
    ) -> Self {
        let mut ri = RealInode {
            layer,
            in_upper_layer,
            inode,
            whiteout,
            opaque,
            stat: None,
        };
        match ri.stat64_ignore_enoent(&Context::default()) {
            Ok(v) => {
                ri.stat = v;
            }
            Err(e) => {
                error!("stat64 failed during RealInode creation: {}", e);
            }
        }
        ri
    }

    pub(crate) fn stat64_ignore_enoent(&self, ctx: &Context) -> Result<Option<stat64>> {
        let layer = self.layer.as_ref();
        match layer.getattr(ctx, self.inode, None) {
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

    // Do real lookup action in specific layer, this call will increase Entry refcount which must be released later.
    fn lookup_child_ignore_enoent(&self, ctx: &Context, name: &str) -> Result<Option<Entry>> {
        let cname = CString::new(name).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        // Real inode must have a layer.
        let layer = self.layer.as_ref();
        match layer.lookup(ctx, self.inode, cname.as_c_str()) {
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

    // Find child inode in same layer under this directory(Self).
    // Return None if not found.
    pub(crate) fn lookup_child(&self, ctx: &Context, name: &str) -> Result<Option<RealInode>> {
        if self.whiteout {
            return Ok(None);
        }

        let layer = self.layer.as_ref();

        // Find child Entry with <name> under directory with inode <self.inode>.
        match self.lookup_child_ignore_enoent(ctx, name)? {
            Some(v) => {
                // The Entry must be forgotten in each layer, which will be done automatically by Drop operation.
                let (whiteout, opaque) = if utils::is_dir(v.attr) {
                    (false, layer.is_opaque(ctx, v.inode)?)
                } else {
                    (layer.is_whiteout(ctx, v.inode)?, false)
                };

                Ok(Some(RealInode {
                    layer: self.layer.clone(),
                    in_upper_layer: self.in_upper_layer,
                    inode: v.inode,
                    whiteout: whiteout,
                    opaque: opaque,
                    stat: Some(v.attr),
                }))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn mkdir(
        &self,
        ctx: &Context,
        name: &str,
        mode: u32,
        umask: u32,
    ) -> Result<RealInode> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let cname = utils::to_cstring(name)?;
        let entry = self
            .layer
            .mkdir(ctx, self.inode, cname.as_c_str(), mode, umask)?;

        // update node's first_layer
        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: self.in_upper_layer,
            inode: entry.inode,
            whiteout: false,
            opaque: false,
            stat: Some(entry.attr),
        })
    }

    pub(crate) fn create(
        &self,
        ctx: &Context,
        name: &str,
        args: CreateIn,
    ) -> Result<(RealInode, Option<u64>)> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let (entry, h, _, _) =
            self.layer
                .create(ctx, self.inode, utils::to_cstring(name)?.as_c_str(), args)?;

        Ok((
            RealInode {
                layer: self.layer.clone(),
                in_upper_layer: self.in_upper_layer,
                inode: entry.inode,
                whiteout: false,
                opaque: false,
                stat: Some(entry.attr),
            },
            h,
        ))
    }

    // Create a symlink in dir(self).
    pub(crate) fn symlink(
        &self,
        ctx: &Context,
        link_name: &str,
        filename: &str,
    ) -> Result<RealInode> {
        if !self.in_upper_layer {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let entry = self.layer.symlink(
            ctx,
            utils::to_cstring(link_name)?.as_c_str(),
            self.inode,
            utils::to_cstring(filename)?.as_c_str(),
        )?;

        Ok(RealInode {
            layer: self.layer.clone(),
            in_upper_layer: self.in_upper_layer,
            inode: entry.inode,
            whiteout: false,
            opaque: false,
            stat: Some(entry.attr),
        })
    }
}

impl Drop for RealInode {
    fn drop(&mut self) {
        // Release refcount of inode in layer.
        let ctx = Context::default();
        let layer = self.layer.as_ref();
        let inode = self.inode;
        debug!("forget inode {} by 1 for backend inode in layer ", inode);
        layer.forget(&ctx, inode, 1);
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

        for (_, child) in self.childrens() {
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
        let (layer, _, inode) = self.first_layer_inode();
        let (h, o, _) = layer.as_ref().open(ctx, inode, flags, fuse_flags)?;
        Ok((layer, h, o))
    }

    pub fn in_upper_layer(&self) -> bool {
        self.upper_inode.lock().unwrap().is_some()
    }

    pub fn upper_layer_only(&self) -> bool {
        self.lower_inodes.is_empty()
    }

    pub fn first_layer_inode(&self) -> (Arc<BoxedLayer>, bool, u64) {
        // It must have either upper inode or one lower inode.
        match self.upper_inode.lock().unwrap().as_ref() {
            Some(v) => (v.layer.clone(), v.in_upper_layer, v.inode),
            None => (
                self.lower_inodes[0].layer.clone(),
                self.lower_inodes[0].in_upper_layer,
                self.lower_inodes[0].inode,
            ),
        }
    }

    pub fn childrens(&self) -> HashMap<String, Arc<OverlayInode>> {
        self.childrens.lock().unwrap().clone()
    }

    pub fn child(&self, name: &str) -> Option<Arc<OverlayInode>> {
        self.childrens.lock().unwrap().get(name).cloned()
    }

    pub fn remove_child(&self, name: &str) {
        self.childrens.lock().unwrap().remove(name);
    }

    pub fn insert_child(&self, name: &str, node: Arc<OverlayInode>) {
        self.childrens
            .lock()
            .unwrap()
            .insert(name.to_string(), node);
    }

    pub fn clear_childrens(&self) {
        self.childrens.lock().unwrap().clear();
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
            deleted_inodes: Mutex::new(HashMap::new()),
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
            let real = RealInode::new(layer.clone(), true, ino, false, false);
            root.upper_inode = Mutex::new(Some(real));
        }

        // Update lower inodes.
        for layer in self.lower_layers.iter() {
            let ino = layer.root_inode();
            let real = RealInode::new(
                Arc::clone(layer),
                false,
                ino,
                false,
                layer.is_opaque(&ctx, ino)?,
            );

            root.lower_inodes.push(real);
        }
        let root_node = Arc::new(root);

        // insert root inode into hash
        self.insert_inode(root_node.inode, Arc::clone(&root_node));

        info!("loading root directory\n");
        self.load_directory(&ctx, Arc::clone(&root_node))?;

        self.root = Some(root_node);

        Ok(())
    }

    pub fn import(&self) -> Result<()> {
        Ok(())
    }

    pub fn make_overlay_inode(&self, real_inode: RealInode) -> Result<OverlayInode> {
        let mut new = OverlayInode::new();
        // FIXME: inode can be reclaimed, we need a better inode allocator. @fangcun.zw
        new.inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        if new.inode > VFS_MAX_INO {
            error!("reached maximum inode number: {}", VFS_MAX_INO);
            // FIXME: try to reclaim! @fangcun.zw
            return Err(Error::new(
                ErrorKind::Other,
                format!("maximum inode number {} reached", VFS_MAX_INO),
            ));
        }

        new.whiteout.store(real_inode.whiteout, Ordering::Relaxed);
        new.lookups = AtomicU64::new(1);
        if let Some(st) = real_inode.stat {
            new.st_ino = st.st_ino;
            new.st_dev = st.st_dev;
            new.mode = st.st_mode;
            new.entry_type = entry_type_from_mode(st.st_mode) as u32;
        }
        if real_inode.in_upper_layer {
            new.upper_inode = Mutex::new(Some(real_inode));
        } else {
            new.lower_inodes.push(real_inode);
        }

        Ok(new)
    }

    fn insert_inode(&self, inode: u64, node: Arc<OverlayInode>) {
        self.inodes.lock().unwrap().insert(inode, node);
    }

    fn get_inode(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        self.inodes.lock().unwrap().get(&inode).cloned()
    }

    fn get_deleted_inode(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        self.deleted_inodes.lock().unwrap().get(&inode).cloned()
    }

    // Return 'totally' deleted inodes from both self.inodes and self.deleted_inodes.
    fn remove_inode(&self, inode: u64) -> Option<Arc<OverlayInode>> {
        let removed = match self.inodes.lock().unwrap().remove(&inode) {
            Some(v) => {
                // Refcount is not 0, we have to delay the removal.
                if v.lookups.load(Ordering::Relaxed) > 0 {
                    self.deleted_inodes.lock().unwrap().insert(inode, v.clone());
                    return None;
                }
                Some(v)
            }
            None => {
                // If the inode is not in hash, it must be in deleted_inodes.
                let mut all_deleted = self.deleted_inodes.lock().unwrap();
                match all_deleted.get(&inode) {
                    Some(v) => {
                        // Refcount is 0, the inode can be removed now.
                        if v.lookups.load(Ordering::Relaxed) == 0 {
                            all_deleted.remove(&inode)
                        } else {
                            // Refcount is not 0, the inode will be removed later.
                            None
                        }
                    }
                    None => None,
                }
            }
        };

        // NOT NECESSARY ANY MORE SINCE FORGET WILL BE CALLED IN DROP.
        // Call forget to release inodes for every layer.
        // let ctx = Context::default();
        // if let Some(v) = removed.clone().as_ref() {
        //     for ri in &v.lower_inodes {
        //         let layer = ri.layer.as_ref();
        //         // FIXME: find what is exact number instead of max_u64 to pass here. @fangcun.zw
        //         layer.forget(&ctx, ri.inode.load(Ordering::Relaxed), u64::MAX);
        //     }

        //     if let Some(ri) = v.upper_inode.lock().unwrap().as_ref() {
        //         let layer = ri.layer.as_ref();
        //         // FIXME: find what is exact number instead of max_u64 to pass here. @fangcun.zw
        //         layer.forget(&ctx, ri.inode.load(Ordering::Relaxed), u64::MAX);
        //     }
        // }

        removed
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
        let pnode = match self.get_inode(parent) {
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
        if let Some(v) = pnode.child(name) {
            return Ok(v);
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
            if let Some(child) = ri.lookup_child(ctx, name)? {
                node_inited = true;
                new = self.make_overlay_inode(child)?;
                // FIXME: check whiteout and opaque flag? @weizhang555
            }
        }

        'layer_loop: for ri in &pnode.lower_inodes {
            // Find an entry.
            if let Some(child) = ri.lookup_child(ctx, name)? {
                // TODO: not sure if this part is correct。  @weizhang555.zw
                if !node_inited {
                    node_inited = true;
                    let whiteout = child.whiteout;
                    let opaque = child.opaque;
                    let stat = child.stat.clone();
                    new = self.make_overlay_inode(child)?;

                    // This is whiteout, no need to check lower layers.
                    if whiteout {
                        break 'layer_loop;
                    }

                    // not whiteout, must have stat
                    match stat {
                        Some(st) => {
                            // A non-directory file shadows all lower layers as default.
                            if !utils::is_dir(st) {
                                break 'layer_loop;
                            }

                            // Opaque directory shadows all lower layers.
                            if opaque {
                                break 'layer_loop;
                            }
                        }
                        None => return Err(Error::from_raw_os_error(libc::EINVAL)),
                    }
                } else {
                    // should stop?
                    if child.whiteout {
                        break 'layer_loop;
                    }

                    // not whiteout, must have stat
                    let st = child.stat.ok_or(Error::from_raw_os_error(libc::EINVAL))?;
                    if !utils::is_dir(st) {
                        break 'layer_loop;
                    }

                    let opaque = child.opaque;
                    // directory
                    new.lower_inodes.push(child);
                    if opaque {
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
            self.insert_inode(new_node.inode, Arc::clone(&new_node));
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

    // As a debug function, print all inode numbers in hash table.
    fn debug_print_all_inodes(&self) {
        let inodes = self.inodes.lock().unwrap();
        // Convert the HashMap to Vector<(inode, pathname)>
        let mut all_inodes = inodes
            .iter()
            .map(|(inode, ovi)| (inode, ovi.path.clone(), ovi.lookups.load(Ordering::Relaxed)))
            .collect::<Vec<_>>();
        all_inodes.sort_by(|a, b| a.0.cmp(b.0));
        trace!("all inodes: {:?}", all_inodes);
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
        if let Some(v) = self.get_inode(inode) {
            return Some(v);
        }

        None
    }

    // Load directory entries from one specific layer, layer can be upper or some one of lower layers.
    pub fn load_directory_layer(
        &self,
        ctx: &Context,
        ovl_inode: u64,
        real: &RealInode,
    ) -> Result<()> {
        if real.whiteout {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if let Some(st) = real.stat64_ignore_enoent(ctx)? {
            if !utils::is_dir(st) {
                return Err(Error::from_raw_os_error(libc::ENOTDIR));
            }

            // process this directory
            let l = real.layer.as_ref();
            let rinode = real.inode;

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
        let upper_inode = node.upper_inode.lock().unwrap();
        let tmp_ui = upper_inode.as_ref();

        if let Some(ref ui) = tmp_ui {
            debug!("load upper for '{}'", node.path.as_str());
            // upper layer
            if ui.whiteout {
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
                self.load_directory_layer(ctx, node.inode, ui)?;
            }

            // if opaque, stop here
            if ui.opaque {
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
            if ri.whiteout {
                break 'layer_loop;
            }

            if let Some(st) = ri.stat64_ignore_enoent(ctx)? {
                if !utils::is_dir(st) {
                    debug!("{} is not a directory", node.path.as_str());
                    // not directory
                    break 'layer_loop;
                }

                // process this layer
                if let Err(e) = self.load_directory_layer(ctx, node.inode, &ri) {
                    if let Some(raw_error) = e.raw_os_error() {
                        if raw_error == libc::ENOENT {
                            continue 'layer_loop;
                        }
                    }

                    return Err(e);
                }
            }

            // if opaque, stop here
            if ri.opaque {
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

        node.clear_childrens();
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

        let v = match self.get_inode(inode) {
            Some(n) => n,
            None => match self.get_deleted_inode(inode) {
                Some(n) => n,
                None => {
                    trace!("forget unknown inode: {}", inode);
                    return;
                }
            },
        };
        // lock up lookups
        // TODO: need atomic protection around lookups' load & store. @fangcun.zw
        let mut lookups = v.lookups.load(Ordering::Relaxed);

        if lookups < count {
            lookups = 0;
        } else {
            lookups -= count;
        }
        v.lookups.store(lookups, Ordering::Relaxed);

        if lookups == 0 {
            debug!("inode is forgotten: {}, name {}", inode, v.name);
            let _ = self.remove_inode(inode);
            let parent = v.parent.lock().unwrap();

            if let Some(p) = parent.upgrade() {
                // remove it from hashmap
                p.remove_child(v.name.as_str());
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
        let tmp = node.lookups.fetch_add(1, Ordering::Relaxed);
        trace!("lookup count: {}", tmp + 1);
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
        match self.get_inode(inode) {
            Some(ovl) => {
                // Find upper layer.
                let upper_inode = ovl.upper_inode.lock().unwrap();
                let real_inode = upper_inode
                    .as_ref()
                    .or_else(|| {
                        if !ovl.lower_inodes.is_empty() {
                            Some(&ovl.lower_inodes[0])
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| Error::new(ErrorKind::Other, "backend inode not found"))?;
                let layer = real_inode.layer.as_ref();
                layer.statfs(ctx, real_inode.inode)
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

        for (_, child) in ovl_inode.childrens() {
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

        let parent_upper_inode = pnode.upper_inode.lock().unwrap();
        match parent_upper_inode.as_ref() {
            Some(parent_ri) => {
                // create directory here
                let st = node.stat64(ctx)?;
                let child = parent_ri.mkdir(ctx, node.name.as_str(), st.st_mode, 0)?;

                // what about st_ino/mode/dev..
                // FIXME: update st_ino/mode/dev, or query it from layer
                // on fly?
                // update node's first_layer
                node.upper_inode.lock().unwrap().replace(child);

                Ok(())
            }
            None => self.create_node_directory(ctx, Arc::clone(&pnode)),
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

        let parent_node = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        // Why lookup again? @weizhang555.zw
        let parent_node = self.lookup_node(ctx, parent_node.inode, "")?;

        let parent_upper_inode = parent_node.upper_inode.lock().unwrap();
        let parent_real_inode = parent_upper_inode
            .as_ref()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        // TODO: why lookup again? @weizhang555.zw
        let self_node = self.lookup_node(ctx, parent_node.inode, node.name.as_str())?;
        let (self_layer, _, self_inode) = self_node.first_layer_inode();

        // Read the linkname from lower layer.
        let path = self_layer.readlink(ctx, self_inode)?;
        // Convert path to &str.
        let path =
            std::str::from_utf8(&path).map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;

        let real_inode = parent_real_inode.symlink(ctx, path, node.name.as_str())?;

        // update first_inode() and upper_inode
        node.upper_inode.lock().unwrap().replace(real_inode);

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

        let parent_node = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
            Arc::clone(n)
        } else {
            return Err(Error::new(ErrorKind::Other, "no parent?"));
        };

        let st = node.stat64(ctx)?;

        // FIXME: why lookup again? @weizhang555
        let parent_node = self.lookup_node(ctx, parent_node.inode, "")?;
        let parent_upper_inode = parent_node.upper_inode.lock().unwrap();
        let parent_real_inode = parent_upper_inode.as_ref().ok_or_else(|| {
            error!("parent {} has no upper inode", parent_node.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?;
        // FIXME: why lookup again? @weizhang555
        let node = self.lookup_node(ctx, parent_node.inode, node.name.as_str())?;
        let (lower_layer, _, lower_inode) = node.first_layer_inode();

        // create the file in upper layer using information from lower layer
        let args = CreateIn {
            flags: 0,
            mode: st.st_mode,
            umask: 0,
            fuse_flags: 0,
        };
        let (upper_real_inode, h) = parent_real_inode.create(ctx, node.name.as_str(), args)?;

        // let dst_handle = h.ok_or_else(|| {
        //     error!("no handle!!!");
        //     Error::new(ErrorKind::Other, "non handle!")
        // })?;
        let upper_handle = h.unwrap_or(0);

        let (h, _, _) = lower_layer.open(ctx, lower_inode, libc::O_RDONLY as u32, 0)?;

        let lower_handle = h.unwrap_or(0);

        // Copy from lower real inode to upper real inode.
        let mut file = TempFile::new().unwrap().into_file();
        let mut offset: usize = 0;
        let size = 4 * 1024 * 1024;
        loop {
            let ret = lower_layer.read(
                ctx,
                lower_inode,
                lower_handle,
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
            let ret = upper_real_inode.layer.write(
                ctx,
                upper_real_inode.inode,
                upper_handle,
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

        // Drop will remove file automatically.
        drop(file);

        // close handles
        lower_layer.release(ctx, lower_inode, 0, lower_handle, true, true, None)?;
        upper_real_inode.layer.release(
            ctx,
            upper_real_inode.inode,
            0,
            upper_handle,
            true,
            true,
            None,
        )?;

        // update upper_inode and first_inode()
        node.upper_inode.lock().unwrap().replace(upper_real_inode);

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
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
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
        let parent_upper_inode = pnode.upper_inode.lock().unwrap();
        let real_pnode = parent_upper_inode.as_ref().ok_or_else(|| {
            error!("parent {} has no upper inode", pnode.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?;
        let real_parent_inode = real_pnode.inode;
        if real_pnode.opaque {
            need_whiteout = false;
        }
        if node.in_upper_layer() {
            if dir {
                real_pnode.layer.rmdir(ctx, real_parent_inode, name)?;
            } else {
                real_pnode.layer.unlink(ctx, real_parent_inode, name)?;
            }
        }

        trace!("toggling children and inodes hash\n");

        // Since node has initial lookup count 1, we have to decrease it by 1 after file removal.
        self.forget_one(node.inode, 1);
        // remove it from hashmap
        pnode.remove_child(node.name.as_str());
        self.remove_inode(node.inode);

        let sname = name.to_string_lossy().into_owned().to_owned();

        if need_whiteout {
            trace!("do_rm: creating whiteout\n");
            real_pnode
                .layer
                .create_whiteout(ctx, real_parent_inode, name)?;
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
            Some(ref rh) => {
                let real_handle = rh.handle.load(Ordering::Relaxed);
                // TODO: check if it's in upper layer? @weizhang555
                if syncdir {
                    rh.layer.fsyncdir(ctx, rh.inode, datasync, real_handle)
                } else {
                    rh.layer.fsync(ctx, rh.inode, datasync, real_handle)
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
        let node_upper_inode = node.upper_inode.lock().unwrap();
        let real_node = node_upper_inode.as_ref().ok_or_else(|| {
            error!("node {} has no upper inode", node.inode);
            Error::from_raw_os_error(libc::EINVAL)
        })?;
        let layer = real_node.layer.as_ref();
        let real_inode = real_node.inode;

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

                // delete the child
                self.remove_inode(child.inode);
                node.remove_child(child.name.as_str());
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

        let (layer, real_parent, pnode) = {
            let pnode = if let Some(ref n) = node.parent.lock().unwrap().upgrade() {
                Arc::clone(n)
            } else {
                return Err(Error::new(ErrorKind::Other, "no parent"));
            };

            let (first_layer, _, first_inode) = pnode.first_layer_inode();
            (first_layer, first_inode, Arc::clone(&pnode))
        };

        // delete white out and update hash
        layer.delete_whiteout(
            ctx,
            real_parent,
            utils::to_cstring(node.name.as_str())?.as_c_str(),
        )?;

        self.remove_inode(node.inode);
        pnode.remove_child(node.name.as_str());

        Ok(())
    }

    pub fn find_real_info_from_handle(
        &self,
        handle: Handle,
    ) -> Result<(Arc<BoxedLayer>, Inode, Handle)> {
        match self.handles.lock().unwrap().get(&handle) {
            Some(h) => match h.real_handle {
                Some(ref rhd) => {
                    return Ok((
                        rhd.layer.clone(),
                        rhd.inode,
                        rhd.handle.load(Ordering::Relaxed),
                    ));
                }
                None => {
                    return Err(Error::from_raw_os_error(libc::ENOENT));
                }
            },

            None => Err(Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    pub fn find_real_inode(&self, inode: Inode) -> Result<(Arc<BoxedLayer>, Inode)> {
        if let Some(n) = self.inodes.lock().unwrap().get(&inode) {
            let (first_layer, _, first_inode) = n.first_layer_inode();
            return Ok((first_layer, first_inode));
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
            let (layer, is_upper_layer, inode) = node.first_layer_inode();
            let handle_data = HandleData {
                node: Arc::clone(&node),
                offset: 0,
                real_handle: Some(RealHandle {
                    layer: layer,
                    in_upper_layer: is_upper_layer,
                    inode: inode,
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
