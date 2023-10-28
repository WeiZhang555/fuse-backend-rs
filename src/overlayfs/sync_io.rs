// Copyright (C) 2023 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::ffi::CStr;
use std::io::Result;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::abi::fuse_abi::{stat64, statvfs64, CreateIn};
use crate::api::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

use libc;
use std::io::{Error, ErrorKind};

impl FileSystem for OverlayFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> Result<FsOptions> {
        // use vfs' negotiated capability if imported
        // other wise, do our own negotiation
        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;

        if self.config.do_import {
            self.import()?;
        }

        if (!self.config.do_import || self.config.writeback)
            && capable.contains(FsOptions::WRITEBACK_CACHE)
        {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        if (!self.config.do_import || self.config.no_open)
            && capable.contains(FsOptions::ZERO_MESSAGE_OPEN)
        {
            opts |= FsOptions::ZERO_MESSAGE_OPEN;
            opts.remove(FsOptions::ATOMIC_O_TRUNC);
            self.no_open.store(true, Ordering::Relaxed);
        }

        if (!self.config.do_import || self.config.no_opendir)
            && capable.contains(FsOptions::ZERO_MESSAGE_OPENDIR)
        {
            opts |= FsOptions::ZERO_MESSAGE_OPENDIR;
            self.no_opendir.store(true, Ordering::Relaxed);
        }

        if (!self.config.do_import || self.config.killpriv_v2)
            && capable.contains(FsOptions::HANDLE_KILLPRIV_V2)
        {
            opts |= FsOptions::HANDLE_KILLPRIV_V2;
            self.killpriv_v2.store(true, Ordering::Relaxed);
        }

        if self.config.perfile_dax && capable.contains(FsOptions::PERFILE_DAX) {
            opts |= FsOptions::PERFILE_DAX;
            self.perfile_dax.store(true, Ordering::Relaxed);
        }

        Ok(opts)
    }

    fn destroy(&self) {}

    fn statfs(&self, ctx: &Context, inode: Inode) -> Result<statvfs64> {
        trace!("STATFS: inode: {}\n", inode);
        self.do_statvfs(ctx, inode)
    }

    fn lookup(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<Entry> {
        let tmp = name.to_string_lossy().to_string();
        trace!("LOOKUP: parent: {}, name: {}\n", parent, tmp);
        let result = self.do_lookup(ctx, parent, tmp.as_str());
        if result.is_ok() {
            trace!("LOOKUP result: {:?}", result.as_ref().unwrap());
        }
        self.debug_print_all_inodes();
        result
    }

    fn forget(&self, _ctx: &Context, inode: Inode, count: u64) {
        trace!("FORGET: inode: {}, count: {}\n", inode, count);
        self.forget_one(inode, count);
        self.debug_print_all_inodes();
    }

    fn batch_forget(&self, _ctx: &Context, requests: Vec<(Inode, u64)>) {
        trace!("BATCH_FORGET: requests: {:?}\n", requests);
        for (inode, count) in requests {
            self.forget_one(inode, count);
        }
    }

    fn opendir(
        &self,
        ctx: &Context,
        inode: Inode,
        _flags: u32,
    ) -> Result<(Option<Handle>, OpenOptions)> {
        trace!("OPENDIR: inode: {}\n", inode);
        if self.no_opendir.load(Ordering::Relaxed) {
            info!("fuse: opendir is not supported.");
            return Err(Error::from_raw_os_error(libc::ENOSYS));
        }

        let mut opts = OpenOptions::empty();

        if let CachePolicy::Always = self.config.cache_policy {
            opts |= OpenOptions::KEEP_CACHE;
        }

        // lookup node
        let node = self.lookup_node(ctx, inode, ".")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid inode number"));
        }

        let st = node.stat64(ctx)?;
        if !utils::is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);

        // reload directory?
        self.reload_directory(ctx, Arc::clone(&node))?;

        //let mut cs = Vec::new();
        //add myself as "."
        //let mut self_node = Arc::clone(&node);
        // self_node.name = ".".to_string();
        // cs.push(self_node);

        // //add parent
        // let mut parent_node = match node.parent.lock().unwrap().upgrade() {
        //     Some(p) => p.clone(),
        //     None => Arc::clone(self.root.as_ref().ok_or_else(|| {
        //         error!("OPENDIR: root is none");
        //         Error::from_raw_os_error(libc::ENOENT)
        //     })?),
        // };
        // parent_node.name = "..".to_string();
        // cs.push(parent_node);

        // for (_, child) in node.childrens.lock().unwrap().iter() {
        //     // skip whiteout node
        //     if child.whiteout.load(Ordering::Relaxed) || child.hidden.load(Ordering::Relaxed) {
        //         continue;
        //     }
        //     // *child.lookups.lock().unwrap() += 1;
        //     cs.push(Arc::clone(child));
        // }

        // TODO: is this necessary to increase lookup count? @weizhang555
        // for c in cs.iter() {
        //     c.lookups.fetch_add(1, Ordering::Relaxed);
        // }

        //node.lookups.fetch_add(1, Ordering::Relaxed);

        self.handles.lock().unwrap().insert(
            handle,
            Arc::new(HandleData {
                node: Arc::clone(&node),
                //               childrens: Some(cs),
                offset: 0,
                real_handle: None,
            }),
        );

        Ok((Some(handle), opts))
    }

    fn releasedir(&self, _ctx: &Context, inode: Inode, _flags: u32, handle: Handle) -> Result<()> {
        trace!("RELEASEDIR: inode: {}, handle: {}\n", inode, handle);
        if self.no_opendir.load(Ordering::Relaxed) {
            info!("fuse: releasedir is not supported.");
            return Err(Error::from_raw_os_error(libc::ENOSYS));
        }
        // {
        //     if let Some(v) = self.handles.lock().unwrap().get(&handle) {
        //         for child in v.node.childrens().values() {
        //             self.forget_one(child.inode, 1);
        //         }

        //         self.forget_one(v.node.inode, 1);
        //     }
        // }

        self.handles.lock().unwrap().remove(&handle);

        Ok(())
    }

    // for mkdir or create file
    // 1. lookup name, if exists and not whiteout, return EEXIST
    // 2. not exists and no whiteout, copy up parent node, ususally  a mkdir on upper layer would do the work
    // 3. find whiteout, if whiteout in upper layer, should set opaque. if in lower layer, just mkdir?
    fn mkdir(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> Result<Entry> {
        let mut delete_whiteout: bool = false;
        let mut has_whiteout: bool = false;
        let mut upper_layer_only: bool = false;
        let mut _opaque = false;
        let mut node: Arc<OverlayInode> = Arc::new(OverlayInode::default());
        let sname = name.to_string_lossy().to_string();

        trace!("MKDIR: parent: {}, name: {}\n", parent, sname);

        if let Some(n) = self.lookup_node_ignore_enoent(ctx, parent, sname.as_str())? {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            node = Arc::clone(&n);
            has_whiteout = true;
        }

        let upper = self
            .upper_layer
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        if has_whiteout {
            if node.in_upper_layer() {
                // whiteout in upper layer, other lower layers are readonly, don't try to delete it
                delete_whiteout = true;
            }

            if node.upper_layer_only() {
                upper_layer_only = true;
            }
        }

        let pnode = self.lookup_node(ctx, parent, "")?;
        // actual work to copy pnode up..
        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        let real_pnode =
            Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                error!("MKDIR: parent upper inode is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?);

        let real_parent_inode = real_pnode.inode.load(Ordering::Relaxed);

        if delete_whiteout {
            let _ = upper.delete_whiteout(ctx, real_parent_inode, name);
        }

        // create dir in upper layer
        let entry = upper.mkdir(ctx, real_parent_inode, name, mode, umask)?;

        if !upper_layer_only {
            upper.set_opaque(ctx, entry.inode)?;
            _opaque = true;
        }

        pnode.loaded.store(false, Ordering::Relaxed);
        // remove whiteout node from child and inode hash
        // FIXME: maybe a reload from start better
        if has_whiteout {
            pnode.remove_child(sname.as_str());
            self.remove_inode(node.inode);
        }

        let entry = self.do_lookup(ctx, parent, sname.as_str());

        pnode.loaded.store(true, Ordering::Relaxed);

        entry
    }

    fn rmdir(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<()> {
        trace!(
            "RMDIR: parent: {}, name: {}\n",
            parent,
            name.to_string_lossy()
        );
        self.do_rm(ctx, parent, name, true)
    }

    fn readdir(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        trace!("READDIR: inode: {}, handle: {}\n", inode, handle);
        if self.config.no_readdir {
            info!("fuse: readdir is not supported.");
            return Ok(());
        }
        self.do_readdir(ctx, inode, handle, size, offset, false, &mut |dir_entry,
                                                                       _|
         -> Result<
            usize,
        > {
            add_entry(dir_entry)
        })
    }

    fn readdirplus(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        trace!("READDIRPLUS: inode: {}, handle: {}\n", inode, handle);
        if self.config.no_readdir {
            info!("fuse: readdirplus is not supported.");
            return Ok(());
        }
        self.do_readdir(ctx, inode, handle, size, offset, true, &mut |dir_entry,
                                                                      entry|
         -> Result<
            usize,
        > {
            match entry {
                Some(e) => add_entry(dir_entry, e),
                None => Err(Error::from_raw_os_error(libc::ENOENT)),
            }
        })
    }

    fn open(
        &self,
        ctx: &Context,
        inode: Inode,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<(Option<Handle>, OpenOptions, Option<u32>)> {
        // open assume file always exist
        trace!("OPEN: inode: {}, flags: {}\n", inode, flags);
        if self.no_open.load(Ordering::Relaxed) {
            info!("fuse: open is not supported.");
            return Err(Error::from_raw_os_error(libc::ENOSYS));
        }

        let readonly: bool = flags
            & (libc::O_APPEND | libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_WRONLY)
                as u32
            == 0;
        // toggle flags
        let mut flags: i32 = flags as i32;

        flags |= libc::O_NOFOLLOW;

        // FIXME: why need this? @weizhang555
        // if cfg!(target_os = "linux") {
        //     flags &= !libc::O_DIRECT;
        // }

        if self.config.writeback {
            if flags & libc::O_ACCMODE == libc::O_WRONLY {
                flags &= !libc::O_ACCMODE;
                flags |= libc::O_RDWR;
            }

            if flags & libc::O_APPEND != 0 {
                flags &= !libc::O_APPEND;
            }
        }
        // lookup node
        let node = self.lookup_node(ctx, inode, "")?;

        // whiteout node
        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !readonly {
            // copy up to upper layer
            self.copy_node_up(ctx, Arc::clone(&node))?;
        }

        // assign a handle in overlayfs and open it
        let (_l, h, _) = node.open(ctx, flags as u32, fuse_flags)?;
        match h {
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
            Some(handle) => {
                let hd = self.next_handle.fetch_add(1, Ordering::Relaxed);
                let handle_data = HandleData {
                    node: Arc::clone(&node),
                    //               childrens: None,
                    offset: 0,
                    real_handle: Some(RealHandle {
                        real_inode: node.first_inode(),
                        handle: AtomicU64::new(handle),
                        invalid: AtomicBool::new(false),
                    }),
                };

                self.handles
                    .lock()
                    .unwrap()
                    .insert(hd, Arc::new(handle_data));

                let mut opts = OpenOptions::empty();
                match self.config.cache_policy {
                    CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
                    CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
                    _ => {}
                }

                trace!("OPEN: returning handle: {}", hd);

                Ok((Some(hd), opts, None))
            }
        }
    }

    fn release(
        &self,
        ctx: &Context,
        _inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> Result<()> {
        trace!(
            "RELEASE: inode: {}, flags: {}, handle: {}, flush: {}, flock_release: {}, lock_owner: {:?}\n",
            _inode,
            flags,
            handle,
            flush,
            flock_release,
            lock_owner
        );

        if self.no_open.load(Ordering::Relaxed) {
            info!("fuse: release is not supported.");
            return Err(Error::from_raw_os_error(libc::ENOSYS));
        }

        if let Some(hd) = self.handles.lock().unwrap().get(&handle) {
            let rh = if let Some(ref h) = hd.real_handle {
                h
            } else {
                return Err(Error::new(ErrorKind::Other, "no handle"));
            };
            let real_handle = rh.handle.load(Ordering::Relaxed);
            let ri = Arc::clone(&rh.real_inode);
            let real_inode = ri.inode.load(Ordering::Relaxed);
            let l = &ri.layer.as_ref().cloned().ok_or_else(|| {
                error!("RELEASE: real inode layer is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?;
            l.release(
                ctx,
                real_inode,
                flags,
                real_handle,
                flush,
                flock_release,
                lock_owner,
            )?;
        }

        self.handles.lock().unwrap().remove(&handle);

        Ok(())
    }

    fn create(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        args: CreateIn,
    ) -> Result<(Entry, Option<Handle>, OpenOptions, Option<u32>)> {
        let mut is_whiteout = false;
        let sname = name.to_string_lossy().to_string();
        trace!("CREATE: parent: {}, name: {}\n", parent, sname);

        let upper = self
            .upper_layer
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        let node = self.lookup_node_ignore_enoent(ctx, parent, sname.as_str())?;

        let mut hargs = args;

        let mut flags: i32 = args.flags as i32;

        flags |= libc::O_NOFOLLOW;
        //        flags &= !libc::O_DIRECT;
        if self.config.writeback {
            if flags & libc::O_ACCMODE == libc::O_WRONLY {
                flags &= !libc::O_ACCMODE;
                flags |= libc::O_RDWR;
            }

            if flags & libc::O_APPEND != 0 {
                flags &= !libc::O_APPEND;
            }
        }

        hargs.flags = flags as u32;

        if let Some(ref n) = node {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            } else {
                is_whiteout = true;
            }
        }

        // no entry or whiteout
        let pnode = self.lookup_node(ctx, parent, "")?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;
        //assert!(pnode.upper_inode.lock().unwrap().is_some());

        let real_parent_inode = pnode.first_inode().inode.load(Ordering::Relaxed);

        // need to delete whiteout?
        if is_whiteout {
            let node = Arc::clone(node.as_ref().unwrap());
            let first_inode = node.first_inode();
            let first_layer = first_inode.layer.as_ref().ok_or_else(|| {
                error!("CREATE: first inode layer is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?;
            if node.in_upper_layer() {
                // whiteout in upper layer, need to delete
                first_layer.delete_whiteout(ctx, real_parent_inode, name)?;
            }

            // delete inode from inodes and childrens
            self.remove_inode(node.inode);
            pnode.remove_child(sname.as_str());
        }

        let (_entry, h, _, _) = upper.create(ctx, real_parent_inode, name, hargs)?;

        // record inode, handle
        // lookup will insert inode into children and inodes hash
        //let real_inode = Arc::new(RealInode {
        // 	layer: Arc::clone(&upper_layer),
        //	inode: entry.inode,
        //	whiteout: AtomicBool::new(false),
        //	opaque: AtomicBool::new(false),
        //	hidden: AtomicBool::new(false),
        //	invalid: AtomicBool::new(false),
        //});

        pnode.loaded.store(false, Ordering::Relaxed);
        let node = self.lookup_node(ctx, parent, sname.as_str())?;
        pnode.loaded.store(true, Ordering::Relaxed);

        let real_inode =
            Arc::clone(node.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                error!("CREATE: node {}'s upper inode is none", node.inode);
                Error::from_raw_os_error(libc::EINVAL)
            })?);

        let final_handle = match h {
            Some(hd) => {
                if self.no_open.load(Ordering::Relaxed) {
                    None
                } else {
                    let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                    let handle_data = HandleData {
                        node: Arc::clone(&node),
                        //               childrens: None,
                        offset: 0,
                        real_handle: Some(RealHandle {
                            real_inode: Arc::clone(&real_inode),
                            handle: AtomicU64::new(hd),
                            invalid: AtomicBool::new(false),
                        }),
                    };
                    self.handles
                        .lock()
                        .unwrap()
                        .insert(handle, Arc::new(handle_data));
                    Some(handle)
                }
            }
            None => None,
        };

        // return data
        let entry = self.do_lookup(ctx, parent, sname.as_str())?;

        let mut opts = OpenOptions::empty();
        match self.config.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        }

        Ok((entry, final_handle, opts, None))
    }

    fn unlink(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<()> {
        trace!(
            "UNLINK: parent: {}, name: {}\n",
            parent,
            name.to_string_lossy()
        );
        self.do_rm(ctx, parent, name, false)
    }

    fn read(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> Result<usize> {
        trace!(
            "READ: inode: {}, handle: {}, size: {}, offset: {}, lock_owner: {:?}, flags: {}\n",
            inode,
            handle,
            size,
            offset,
            lock_owner,
            flags
        );

        let data = self.get_data(ctx, Some(handle), inode, flags)?;

        match data.real_handle {
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
            Some(ref hd) => {
                let real_handle = hd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&hd.real_inode);
                let (real_inode, layer) = (
                    ri.inode.load(Ordering::Relaxed),
                    Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                        error!("READ: real inode layer is none");
                        Error::from_raw_os_error(libc::EINVAL)
                    })?),
                );

                layer.read(
                    ctx,
                    real_inode,
                    real_handle,
                    w,
                    size,
                    offset,
                    lock_owner,
                    flags,
                )
            }
        }
    }

    fn write(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<usize> {
        trace!(
            "WRITE: inode: {}, handle: {}, size: {}, offset: {}, lock_owner: {:?}, delayed_write: {}, flags: {}, fuse_flags: {}\n",
            inode,
            handle,
            size,
            offset,
            lock_owner,
            delayed_write,
            flags,
            fuse_flags
        );

        let data = self.get_data(ctx, Some(handle), inode, flags)?;

        match data.real_handle {
            None => Err(Error::from_raw_os_error(libc::ENOENT)),
            Some(ref hd) => {
                let real_handle = hd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&hd.real_inode);
                let (real_inode, layer) = (
                    ri.inode.load(Ordering::Relaxed),
                    Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                        error!("WRITE: real inode layer is none");
                        Error::from_raw_os_error(libc::EINVAL)
                    })?),
                );

                layer.write(
                    ctx,
                    real_inode,
                    real_handle,
                    r,
                    size,
                    offset,
                    lock_owner,
                    delayed_write,
                    flags,
                    fuse_flags,
                )
                // remove whiteout node from child and inode hash
            }
        }
    }

    fn getattr(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> Result<(stat64, Duration)> {
        trace!(
            "GETATTR: inode: {}, handle: {}\n",
            inode,
            handle.unwrap_or_default()
        );

        if !self.no_open.load(Ordering::Relaxed) {
            if let Some(h) = handle {
                if let Some(hd) = self.handles.lock().unwrap().get(&h) {
                    if let Some(ref v) = hd.real_handle {
                        let ri = Arc::clone(&v.real_inode);
                        let layer = Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                            error!("GETATTR: real inode layer is none");
                            Error::from_raw_os_error(libc::EINVAL)
                        })?);
                        let real_inode = ri.inode.load(Ordering::Relaxed);
                        let real_handle = v.handle.load(Ordering::Relaxed);
                        let (st, _d) = layer.getattr(ctx, real_inode, Some(real_handle))?;
                        return Ok((st, self.config.attr_timeout));
                    }
                }
            }
        }

        let node = self.lookup_node(ctx, inode, "")?;
        let rl = node.first_inode();
        if let Some(ref v) = rl.layer {
            let layer = Arc::clone(v);
            let real_inode = rl.inode.load(Ordering::Relaxed);

            let (st, _d) = layer.getattr(ctx, real_inode, None)?;
            return Ok((st, self.config.attr_timeout));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    fn setattr(
        &self,
        ctx: &Context,
        inode: Inode,
        attr: stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> Result<(stat64, Duration)> {
        trace!("SETATTR: inode: {}\n", inode);

        // Check if upper layer exists.
        self.upper_layer
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::from_raw_os_error(libc::EROFS))?;

        // deal with handle first
        if !self.no_open.load(Ordering::Relaxed) {
            if let Some(h) = handle {
                if let Some(hd) = self.handles.lock().unwrap().get(&h) {
                    if let Some(ref rhd) = hd.real_handle {
                        let ri = Arc::clone(&rhd.real_inode);
                        let layer = Arc::clone(ri.layer.as_ref().ok_or_else(|| {
                            error!("SETATTR: real inode layer is none");
                            Error::from_raw_os_error(libc::EINVAL)
                        })?);
                        let real_inode = ri.inode.load(Ordering::Relaxed);
                        let real_handle = rhd.handle.load(Ordering::Relaxed);
                        // handle opened in upper layer
                        if ri.in_upper_layer {
                            let (st, _d) =
                                layer.setattr(ctx, real_inode, attr, Some(real_handle), valid)?;

                            return Ok((st, self.config.attr_timeout));
                        }
                    }
                }
            }
        }

        let node = self.lookup_node(ctx, inode, "")?;

        //layer is upper layer
        let node = if !self.node_in_upper_layer(Arc::clone(&node))? {
            self.copy_node_up(ctx, Arc::clone(&node))?
        } else {
            Arc::clone(&node)
        };

        let v = node.first_inode();
        let (layer, real_inode) = (
            Arc::clone(v.layer.as_ref().ok_or_else(|| {
                error!("SETATTR: real inode layer is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?),
            v.inode.load(Ordering::Relaxed),
        );

        let (st, _d) = layer.setattr(ctx, real_inode, attr, None, valid)?;
        Ok((st, self.config.attr_timeout))
    }

    fn rename(
        &self,
        _ctx: &Context,
        _olddir: Inode,
        _odlname: &CStr,
        _newdir: Inode,
        _newname: &CStr,
        _flags: u32,
    ) -> Result<()> {
        // complex, implement it later
        trace!(
            "RENAME: olddir: {}, oldname: {}, newdir: {}, newname: {}, flags: {}\n",
            _olddir,
            _odlname.to_string_lossy(),
            _newdir,
            _newname.to_string_lossy(),
            _flags
        );
        Err(Error::from_raw_os_error(libc::EXDEV))
    }

    fn mknod(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> Result<Entry> {
        let mut is_whiteout = false;
        let sname = name.to_string_lossy().to_string();
        trace!("MKNOD: parent: {}, name: {}\n", parent, sname);

        let node = self.lookup_node_ignore_enoent(ctx, parent, sname.as_str())?;

        if let Some(ref n) = node {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            } else {
                is_whiteout = true;
            }
        }

        // no entry or whiteout
        let pnode = self.lookup_node(ctx, parent, "")?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        let real_parent_inode = pnode.first_inode().inode.load(Ordering::Relaxed);

        // need to delete whiteout?
        if is_whiteout {
            let node = Arc::clone(node.as_ref().ok_or_else(|| {
                error!("MKNOD: node is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?);
            let first_inode = node.first_inode();
            let first_layer = first_inode.layer.as_ref().ok_or_else(|| {
                error!("MKNOD: first inode layer is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?;
            if node.in_upper_layer() {
                // whiteout in upper layer, need to delete
                first_layer.delete_whiteout(ctx, real_parent_inode, name)?;
            }

            // delete inode from inodes and childrens
            self.remove_inode(node.inode);
            pnode.remove_child(sname.as_str());
        }

        // make it
        //assert!(pnode.in_upper_layer());

        let real_inode =
            Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().ok_or_else(|| {
                error!("MKNOD: parent upper inode is none");
                Error::from_raw_os_error(libc::EINVAL)
            })?);
        let layer = Arc::clone(real_inode.layer.as_ref().ok_or_else(|| {
            error!("MKNOD: real inode layer is none");
            Error::from_raw_os_error(libc::EINVAL)
        })?);
        layer.mknod(ctx, real_parent_inode, name, mode, rdev, umask)?;

        pnode.loaded.store(false, Ordering::Relaxed);
        let entry = self.do_lookup(ctx, parent, sname.as_str());
        pnode.loaded.store(true, Ordering::Relaxed);

        entry
    }

    fn link(&self, ctx: &Context, inode: Inode, newparent: Inode, name: &CStr) -> Result<Entry> {
        let sname = name.to_string_lossy().to_string();
        trace!(
            "LINK: inode: {}, newparent: {}, name: {}\n",
            inode,
            newparent,
            sname.as_str()
        );
        // hard link..
        let node = self.lookup_node(ctx, inode, "")?;
        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let newpnode = self.lookup_node(ctx, newparent, "")?;
        if newpnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let newnode = self.lookup_node_ignore_enoent(ctx, newparent, sname.as_str())?;

        // copy node up
        let node = self.copy_node_up(ctx, Arc::clone(&node))?;
        let newpnode = self.copy_node_up(ctx, Arc::clone(&newpnode))?;
        let sname = name.to_string_lossy().into_owned().to_owned();

        if let Some(n) = newnode {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            // need to delete whiteout? if whiteout in upper layer
            // delete it
            if self.node_in_upper_layer(Arc::clone(&n))? {
                // find out the real parent inode and delete whiteout
                let pri = newpnode.first_inode();
                let layer = Arc::clone(pri.layer.as_ref().ok_or_else(|| {
                    error!("LINK: parent first inode layer is none");
                    Error::from_raw_os_error(libc::EINVAL)
                })?);
                let real_parent_inode = pri.inode.load(Ordering::Relaxed);
                layer.delete_whiteout(ctx, real_parent_inode, name)?;
            }

            // delete from hash
            self.remove_inode(n.inode);
            newpnode.remove_child(sname.as_str());
        }

        // create the link
        let pri = newpnode.first_inode();
        let layer = Arc::clone(pri.layer.as_ref().ok_or_else(|| {
            error!("LINK: parent first inode layer is none");
            Error::from_raw_os_error(libc::EINVAL)
        })?);
        let real_parent_inode = pri.inode.load(Ordering::Relaxed);
        let real_inode = node.first_inode().inode.load(Ordering::Relaxed);
        layer.link(ctx, real_inode, real_parent_inode, name)?;

        newpnode.loaded.store(false, Ordering::Relaxed);
        let entry = self.do_lookup(ctx, newparent, sname.as_str());
        newpnode.loaded.store(true, Ordering::Relaxed);

        entry
    }

    fn symlink(&self, ctx: &Context, linkname: &CStr, parent: Inode, name: &CStr) -> Result<Entry> {
        // soft link
        let sname = name.to_string_lossy().into_owned().to_owned();
        trace!(
            "SYMLINK: linkname: {}, parent: {}, name: {}\n",
            linkname.to_string_lossy(),
            parent,
            sname.as_str()
        );

        let pnode = self.lookup_node(ctx, parent, "")?;

        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let node = self.lookup_node_ignore_enoent(ctx, parent, sname.as_str())?;
        if let Some(n) = node {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            // whiteout, may need to delete it
            self.delete_whiteout_node(ctx, Arc::clone(&n))?;

            // delete from hash
            self.remove_inode(n.inode);
            pnode.remove_child(sname.as_str());
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;
        // find out layer, real parent..
        let (layer, real_parent) = {
            let first = pnode.first_inode();
            (
                Arc::clone(first.layer.as_ref().ok_or_else(|| {
                    error!("SYMLINK: parent first inode layer is none");
                    Error::from_raw_os_error(libc::EINVAL)
                })?),
                first.inode.load(Ordering::Relaxed),
            )
        };

        layer.symlink(ctx, linkname, real_parent, name)?;

        pnode.loaded.store(false, Ordering::Relaxed);
        let entry = self.do_lookup(ctx, parent, sname.as_str());
        pnode.loaded.store(true, Ordering::Relaxed);
        entry
    }

    fn readlink(&self, ctx: &Context, inode: Inode) -> Result<Vec<u8>> {
        trace!("READLINK: inode: {}\n", inode);

        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // find out real inode
        let (layer, real_inode) = {
            let first = node.first_inode();
            (
                Arc::clone(first.layer.as_ref().ok_or_else(|| {
                    error!("READLINK: first inode layer is none");
                    Error::from_raw_os_error(libc::EINVAL)
                })?),
                first.inode.load(Ordering::Relaxed),
            )
        };

        layer.readlink(ctx, real_inode)
    }

    fn flush(&self, ctx: &Context, inode: Inode, handle: Handle, lock_owner: u64) -> Result<()> {
        trace!(
            "FLUSH: inode: {}, handle: {}, lock_owner: {}\n",
            inode,
            handle,
            lock_owner
        );

        if self.no_open.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOSYS));
        }

        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // readonly file can also be flushed, pass flush request
        // to lower layer instead of return EROFS here
        // if !self.node_in_upper_layer(Arc::clone(&node))? {
        // in lower layer, error out or just success?
        // FIXME:
        //	return Err(Error::from_raw_os_error(libc::EROFS));
        // }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;

        // FIXME: need to test if inode matches corresponding handle?

        layer.flush(ctx, real_inode, real_handle, lock_owner)
    }

    fn fsync(&self, ctx: &Context, inode: Inode, datasync: bool, handle: Handle) -> Result<()> {
        trace!(
            "FSYNC: inode: {}, datasync: {}, handle: {}\n",
            inode,
            datasync,
            handle
        );

        self.do_fsync(ctx, inode, datasync, handle, false)
    }

    fn fsyncdir(&self, ctx: &Context, inode: Inode, datasync: bool, handle: Handle) -> Result<()> {
        trace!(
            "FSYNCDIR: inode: {}, datasync: {}, handle: {}\n",
            inode,
            datasync,
            handle
        );

        self.do_fsync(ctx, inode, datasync, handle, true)
    }

    fn access(&self, ctx: &Context, inode: Inode, mask: u32) -> Result<()> {
        trace!("ACCESS: inode: {}, mask: {}\n", inode, mask);
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;
        layer.access(ctx, real_inode, mask)
    }

    fn setxattr(
        &self,
        ctx: &Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> Result<()> {
        trace!(
            "SETXATTR: inode: {}, name: {}, value: {:?}, flags: {}\n",
            inode,
            name.to_string_lossy(),
            value,
            flags
        );
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // copy node into upper layer
            // FIXME:
            self.copy_node_up(ctx, Arc::clone(&node))?;
        }

        let _node = self.lookup_node(ctx, inode, "")?;

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.setxattr(ctx, real_inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: &Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> Result<GetxattrReply> {
        trace!(
            "GETXATTR: inode: {}, name: {}, size: {}\n",
            inode,
            name.to_string_lossy(),
            size
        );
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.getxattr(ctx, real_inode, name, size)
    }

    fn listxattr(&self, ctx: &Context, inode: Inode, size: u32) -> Result<ListxattrReply> {
        trace!("LISTXATTR: inode: {}, size: {}\n", inode, size);
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.listxattr(ctx, real_inode, size)
    }

    fn removexattr(&self, ctx: &Context, inode: Inode, name: &CStr) -> Result<()> {
        trace!(
            "REMOVEXATTR: inode: {}, name: {}\n",
            inode,
            name.to_string_lossy()
        );
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // copy node into upper layer
            // FIXME:
            self.copy_node_up(ctx, Arc::clone(&node))?;
        }

        let _node = self.lookup_node(ctx, inode, "")?;

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.removexattr(ctx, real_inode, name)
    }

    fn fallocate(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        trace!(
            "FALLOCATE: inode: {}, handle: {}, mode: {}, offset: {}, length: {}\n",
            inode,
            handle,
            mode,
            offset,
            length
        );
        // Use O_RDONLY flags which indicates no copy up.
        let data = self.get_data(ctx, Some(handle), inode, libc::O_RDONLY as u32)?;

        match data.real_handle {
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
                layer.fallocate(ctx, real_inode, real_handle, mode, offset, length)
            }
        }
    }

    fn lseek(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> Result<u64> {
        trace!(
            "LSEEK: inode: {}, handle: {}, offset: {}, whence: {}\n",
            inode,
            handle,
            offset,
            whence
        );
        // can this be on dir? FIXME: assume file for now
        // we need special process if it can be called on dir
        let node = self.lookup_node(ctx, inode, "")?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let st = node.stat64(ctx)?;
        if utils::is_dir(st) {
            error!("lseek on directory");
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;
        layer.lseek(ctx, real_inode, real_handle, offset, whence)
    }
}
