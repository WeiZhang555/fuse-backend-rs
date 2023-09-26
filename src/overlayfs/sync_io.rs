use super::*;
use std::ffi::{CStr, CString};
use std::io::Result;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::abi::fuse_abi::CreateIn;
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

    fn statfs(&self, ctx: &Context, inode: Inode) -> Result<libc::statvfs64> {
        self.do_statvfs(ctx, inode)
    }

    fn lookup(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<Entry> {
        let tmp = name.to_string_lossy().into_owned().to_owned();
        trace!("LOOKUP: parent: {}, name: {}\n", parent, tmp);
        let node = self.lookup_node(ctx, parent, name)?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let pnode = if let Some(v) = self.get_node_from_inode(parent) {
            v
        } else {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        };

        let _ppath = String::from(pnode.path.as_str());
        let _sname = name.to_string_lossy().into_owned().to_owned();
        let st = node.stat64(ctx)?;

        // load this directory here
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            self.load_directory(ctx, Arc::clone(&node))?;
            node.loaded.store(true, Ordering::Relaxed);
        }

        // FIXME: can forget happen between found and increase reference counter?

        *node.lookups.lock().unwrap() += 1;

        Ok(Entry {
            inode: node.inode as u64,
            generation: 0,
            attr: st, //libc::stat64
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    fn forget(&self, _ctx: &Context, inode: Inode, count: u64) {
        self.forget_one(inode, count)
    }

    fn batch_forget(&self, _ctx: &Context, requests: Vec<(Inode, u64)>) {
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
        let mut opts = OpenOptions::empty();

        match self.config.cache_policy {
            CachePolicy::Always => {
                opts |= OpenOptions::KEEP_CACHE;
            }

            _ => {}
        }

        // lookup node
        let node = self.lookup_node(
            ctx,
            inode,
            CString::new(".").expect("invalid path!").as_c_str(),
        )?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid inode number"));
        }

        let st = node.stat64(ctx)?;
        if st.st_mode & libc::S_IFDIR == 0 {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);

        // reload directory?
        self.reload_directory(ctx, Arc::clone(&node))?;

        let mut cs = Vec::new();
        //add myself
        cs.push(Arc::clone(&node));

        //add parent
        if let Some(p) = node.parent.lock().unwrap().upgrade() {
            cs.push(p);
        } else {
            cs.push(Arc::clone(self.root.as_ref().unwrap()));
        };

        for (_, child) in node.childrens.lock().unwrap().iter() {
            // skip whiteout node
            if child.whiteout.load(Ordering::Relaxed) || child.hidden.load(Ordering::Relaxed) {
                continue;
            }
            // *child.lookups.lock().unwrap() += 1;
            cs.push(Arc::clone(child));
        }

        for c in cs.iter() {
            *c.lookups.lock().unwrap() += 1;
        }

        *node.lookups.lock().unwrap() += 1;

        self.handles.lock().unwrap().insert(
            handle,
            HandleData {
                node: Arc::clone(&node),
                childrens: Some(cs),
                offset: 0,
                real_handle: None,
            },
        );

        Ok((Some(handle), opts))
    }

    fn releasedir(&self, _ctx: &Context, inode: Inode, _flags: u32, handle: Handle) -> Result<()> {
        trace!("RELEASEDIR: inode: {}, handle: {}\n", inode, handle);
        {
            if let Some(v) = self.handles.lock().unwrap().get(&handle) {
                for child in v.childrens.as_ref().unwrap() {
                    self.forget_one(child.inode, 1);
                }

                self.forget_one(v.node.inode, 1);
            }
        }

        trace!("RELEASEDIR: returning");

        self.handles.lock().unwrap().remove(&handle);

        Ok(())
    }

    // for mkdir or create file
    // 1. lookup name, if exists and not whiteout, return EEXIST
    // 2. not exists and no whiteout, copy up parent node, ususally  a mkdir on upper layer would do the work
    // 3. find whiteout, if whiteout in upper layer, shoudl set opaque. if in lower layer, just mkdir?
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

        let sname = name.to_string_lossy().into_owned().to_owned();
        if let Some(n) = self.lookup_node_ignore_enoent(ctx, parent, name)? {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            node = Arc::clone(&n);
            has_whiteout = true;
        }

        let upper = if let Some(l) = self.get_upper_layer() {
            l
        } else {
            return Err(Error::from_raw_os_error(libc::EROFS));
            // return Err(Error::new(ErrorKind::ReadOnlyFilesystem, "readonly filesystem!"));
        };

        if has_whiteout {
            if node.in_upper_layer() {
                // whiteout in upper layer, other lower layers are readonly, don't try to delete it
                delete_whiteout = true;
            }

            if node.upper_layer_only() {
                upper_layer_only = true;
            }
        }

        let pnode = self.lookup_node(
            ctx,
            parent,
            CString::new("").expect("invalid file name").as_c_str(),
        )?;
        // actual work to copy pnode up..
        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        assert!(pnode.in_upper_layer());
        let real_pnode = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());

        let real_parent_inode = real_pnode.inode.load(Ordering::Relaxed);

        if delete_whiteout {
            let _ = upper.delete_whiteout(ctx, real_parent_inode, sname.as_str());
        }

        // create dir in upper layer
        let entry = upper.mkdir(ctx, real_parent_inode, name, mode, umask)?;

        if !upper_layer_only {
            upper.create_opaque_whiteout(ctx, entry.inode)?;
            _opaque = true;
        }

        pnode.loaded.store(false, Ordering::Relaxed);
        // remove whiteout node from child and inode hash
        // FIXME: maybe a reload from start better
        if has_whiteout {
            pnode.childrens.lock().unwrap().remove(sname.as_str());
            self.inodes.lock().unwrap().remove(&node.inode);
        }

        let node = self.lookup_node(ctx, parent, name)?;

        pnode.loaded.store(true, Ordering::Relaxed);

        Ok(Entry {
            inode: node.inode,
            generation: 0,
            attr: node.stat64(ctx)?,
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    fn rmdir(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<()> {
        self.do_rm(ctx, parent, name, true)
    }

    fn readdir(
        &self,
        ctx: &Context,
        _inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(ctx, handle, size, offset, &mut |dir_entry,
                                                         _entry|
         -> Result<usize> {
            add_entry(dir_entry)
        })
    }

    fn readdirplus(
        &self,
        ctx: &Context,
        _inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(ctx, handle, size, offset, &mut |dir_entry,
                                                         entry|
         -> Result<usize> {
            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        ctx: &Context,
        inode: Inode,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<(Option<Handle>, OpenOptions)> {
        // open assume file always exist

        let readonly: bool = flags
            & (libc::O_APPEND | libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_WRONLY)
                as u32
            == 0;

        trace!("OPEN: inode: {}, readonly: {}", inode, readonly);

        // toggle flags
        let mut flags: i32 = flags as i32;

        flags |= libc::O_NOFOLLOW;
        flags &= !libc::O_DIRECT;
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
        let node = self.lookup_node(
            ctx,
            inode,
            CString::new("").expect("invalid c string").as_c_str(),
        )?;

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
        if let Some(handle) = h {
            let hd = self.next_handle.fetch_add(1, Ordering::Relaxed);
            let handle_data = HandleData {
                node: Arc::clone(&node),
                childrens: None,
                offset: 0,
                real_handle: Some(RealHandle {
                    real_inode: Arc::clone(&node.first_inode.lock().unwrap()),
                    handle: AtomicU64::new(handle),
                    invalid: AtomicBool::new(false),
                }),
            };

            self.handles.lock().unwrap().insert(hd, handle_data);

            let mut opts = OpenOptions::empty();
            match self.config.cache_policy {
                CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
                CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
                _ => {}
            }

            trace!("OPEN: returning handle: {}", hd);

            return Ok((Some(hd), opts));
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
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
        if let Some(hd) = self.handles.lock().unwrap().get(&handle) {
            let rh = if let Some(ref h) = hd.real_handle {
                h
            } else {
                return Err(Error::new(ErrorKind::Other, "no handle"));
            };
            let real_handle = rh.handle.load(Ordering::Relaxed);
            let ri = Arc::clone(&rh.real_inode);
            let real_inode = ri.inode.load(Ordering::Relaxed);
            let l = Arc::clone(&ri.layer.as_ref().unwrap());
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
    ) -> Result<(Entry, Option<Handle>, OpenOptions)> {
        let mut is_whiteout = false;
        let node = self.lookup_node_ignore_enoent(ctx, parent, name)?;
        let sname = name.to_string_lossy().into_owned().to_owned();

        let mut hargs = args;

        let mut flags: i32 = args.flags as i32;

        flags |= libc::O_NOFOLLOW;
        flags &= !libc::O_DIRECT;
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
        let pnode = self.lookup_node(
            ctx,
            parent,
            CString::new("").expect("invalid c string").as_c_str(),
        )?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        assert!(pnode.upper_inode.lock().unwrap().is_some());

        let real_parent_inode = pnode
            .first_inode
            .lock()
            .unwrap()
            .inode
            .load(Ordering::Relaxed);

        // need to delete whiteout?
        if is_whiteout {
            let node = Arc::clone(node.as_ref().unwrap());
            let first_inode = Arc::clone(&node.first_inode.lock().unwrap());
            let first_layer = first_inode.layer.as_ref().unwrap();
            if node.in_upper_layer() {
                // whiteout in upper layer, need to delete
                first_layer.delete_whiteout(ctx, real_parent_inode, sname.as_str())?;
            }

            // delete inode from inodes and childrens
            self.inodes.lock().unwrap().remove(&node.inode);
            pnode.childrens.lock().unwrap().remove(sname.as_str());
        }

        // create file in upper layer
        if let Some(ref upper_layer) = self.upper_layer.as_ref() {
            let (_entry, h, _) = upper_layer.create(ctx, real_parent_inode, name, hargs)?;

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
            let node = self.lookup_node(ctx, parent, name)?;
            pnode.loaded.store(true, Ordering::Relaxed);

            let real_inode = Arc::clone(node.upper_inode.lock().unwrap().as_ref().unwrap());

            let final_handle = if let Some(hd) = h {
                let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                let handle_data = HandleData {
                    node: Arc::clone(&node),
                    childrens: None,
                    offset: 0,
                    real_handle: Some(RealHandle {
                        real_inode: Arc::clone(&real_inode),
                        handle: AtomicU64::new(hd),
                        invalid: AtomicBool::new(false),
                    }),
                };
                self.handles.lock().unwrap().insert(handle, handle_data);
                Some(handle)
            } else {
                None
            };

            // return data
            let entry = Entry {
                inode: node.inode,
                generation: 0,
                attr: node.stat64(ctx)?,
                attr_flags: 0,
                attr_timeout: self.config.attr_timeout,
                entry_timeout: self.config.entry_timeout,
            };

            let mut opts = OpenOptions::empty();
            match self.config.cache_policy {
                CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
                CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
                _ => {}
            }

            return Ok((entry, final_handle, opts));
        } else {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        //Err(Error::new(ErrorKind::Other, "Unknown error"))
    }

    fn unlink(&self, ctx: &Context, parent: Inode, name: &CStr) -> Result<()> {
        self.do_rm(ctx, parent, name, false)
    }

    fn read(
        &self,
        ctx: &Context,
        _inode: Inode,
        handle: Handle,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> Result<usize> {
        if let Some(v) = self.handles.lock().unwrap().get(&handle) {
            if let Some(ref hd) = v.real_handle {
                let real_handle = hd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&hd.real_inode);
                let (real_inode, layer) = (
                    ri.inode.load(Ordering::Relaxed),
                    Arc::clone(ri.layer.as_ref().unwrap()),
                );

                return layer.read(
                    ctx,
                    real_inode,
                    real_handle,
                    w,
                    size,
                    offset,
                    lock_owner,
                    flags,
                );
            }
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    fn write(
        &self,
        ctx: &Context,
        _inode: Inode,
        handle: Handle,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
        fuse_flags: u32,
    ) -> Result<usize> {
        if let Some(v) = self.handles.lock().unwrap().get(&handle) {
            if let Some(ref hd) = v.real_handle {
                let real_handle = hd.handle.load(Ordering::Relaxed);
                let ri = Arc::clone(&hd.real_inode);
                let (real_inode, layer) = (
                    ri.inode.load(Ordering::Relaxed),
                    Arc::clone(ri.layer.as_ref().unwrap()),
                );

                return layer.write(
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
                );
                // remove whiteout node from child and inode hash
            }
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    fn getattr(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> Result<(libc::stat64, Duration)> {
        trace!("GETATTR: inode: {}\n", inode);
        if let Some(h) = handle {
            if let Some(hd) = self.handles.lock().unwrap().get(&h) {
                if let Some(ref v) = hd.real_handle {
                    let ri = Arc::clone(&v.real_inode);
                    let layer = Arc::clone(ri.layer.as_ref().unwrap());
                    let real_inode = ri.inode.load(Ordering::Relaxed);
                    let real_handle = v.handle.load(Ordering::Relaxed);
                    let (st, _d) = layer.getattr(ctx, real_inode, Some(real_handle))?;
                    return Ok((st, self.config.attr_timeout));
                }
            }
        } else {
            let node = self.lookup_node(
                ctx,
                inode,
                CString::new("").expect("invalid c string").as_c_str(),
            )?;
            let rl = Arc::clone(&node.first_inode.lock().unwrap());
            if let Some(ref v) = rl.layer {
                let layer = Arc::clone(v);
                let real_inode = rl.inode.load(Ordering::Relaxed);

                let (st, _d) = layer.getattr(ctx, real_inode, None)?;
                return Ok((st, self.config.attr_timeout));
            }
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    fn setattr(
        &self,
        ctx: &Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> Result<(libc::stat64, Duration)> {
        // find out real inode and real handle, if the first
        // layer id not upper layer copy it up

        // deal with handle first
        if let Some(h) = handle {
            if let Some(hd) = self.handles.lock().unwrap().get(&h) {
                if let Some(ref rhd) = hd.real_handle {
                    let ri = Arc::clone(&rhd.real_inode);
                    let layer = Arc::clone(ri.layer.as_ref().unwrap());
                    let real_inode = ri.inode.load(Ordering::Relaxed);
                    let real_handle = rhd.handle.load(Ordering::Relaxed);
                    // handle opened in upper layer
                    if self.is_upper_layer(Arc::clone(&layer)) {
                        let (st, _d) =
                            layer.setattr(ctx, real_inode, attr, Some(real_handle), valid)?;

                        return Ok((st, self.config.attr_timeout));
                    }
                }
            }
        }

        let node = self.lookup_node(
            ctx,
            inode,
            CString::new("").expect("invalid c string").as_c_str(),
        )?;

        //layer is upper layer
        let node = if !self.node_in_upper_layer(Arc::clone(&node))? {
            self.copy_node_up(ctx, Arc::clone(&node))?
        } else {
            Arc::clone(&node)
        };

        let v = Arc::clone(&node.first_inode.lock().unwrap());
        let (layer, real_inode) = (
            Arc::clone(v.layer.as_ref().unwrap()),
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
        let node = self.lookup_node_ignore_enoent(ctx, parent, name)?;
        let sname = name.to_string_lossy().into_owned().to_owned();

        if let Some(ref n) = node {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            } else {
                is_whiteout = true;
            }
        }

        // no entry or whiteout
        let pnode = self.lookup_node(
            ctx,
            parent,
            CString::new("").expect("invalid c string").as_c_str(),
        )?;
        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;

        assert!(pnode.upper_inode.lock().unwrap().is_some());

        let real_parent_inode = pnode
            .first_inode
            .lock()
            .unwrap()
            .inode
            .load(Ordering::Relaxed);

        // need to delete whiteout?
        if is_whiteout {
            let node = Arc::clone(node.as_ref().unwrap());
            let first_inode = Arc::clone(&node.first_inode.lock().unwrap());
            let first_layer = first_inode.layer.as_ref().unwrap();
            if node.in_upper_layer() {
                // whiteout in upper layer, need to delete
                first_layer.delete_whiteout(ctx, real_parent_inode, sname.as_str())?;
            }

            // delete inode from inodes and childrens
            self.inodes.lock().unwrap().remove(&node.inode);
            pnode.childrens.lock().unwrap().remove(sname.as_str());
        }

        // make it
        assert!(pnode.in_upper_layer());

        let real_inode = Arc::clone(pnode.upper_inode.lock().unwrap().as_ref().unwrap());
        let layer = Arc::clone(real_inode.layer.as_ref().unwrap());
        let _entry = layer.mknod(ctx, real_parent_inode, name, mode, rdev, umask)?;

        pnode.loaded.store(false, Ordering::Relaxed);
        let node = self.lookup_node(ctx, parent, name)?;
        pnode.loaded.store(true, Ordering::Relaxed);
        Ok(Entry {
            inode: node.inode,
            generation: 0,
            attr: node.stat64(ctx)?,
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    fn link(&self, ctx: &Context, inode: Inode, newparent: Inode, name: &CStr) -> Result<Entry> {
        // hard link..
        let node = self.lookup_node(
            ctx,
            inode,
            CString::new("").expect("invalic c string").as_c_str(),
        )?;
        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let newpnode = self.lookup_node(
            ctx,
            newparent,
            CString::new("").expect("invalid c string").as_c_str(),
        )?;
        if newpnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let newnode = self.lookup_node_ignore_enoent(ctx, newparent, name)?;

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
                let pri = &newpnode.first_inode.lock().unwrap();
                let layer = Arc::clone(pri.layer.as_ref().unwrap());
                let real_parent_inode = pri.inode.load(Ordering::Relaxed);
                layer.delete_whiteout(ctx, real_parent_inode, sname.as_str())?;
            }

            // delete from hash
            self.inodes.lock().unwrap().remove(&n.inode);
            newpnode.childrens.lock().unwrap().remove(sname.as_str());
        }

        // create the link
        let pri = &newpnode.first_inode.lock().unwrap();
        let layer = Arc::clone(pri.layer.as_ref().unwrap());
        let real_parent_inode = pri.inode.load(Ordering::Relaxed);
        let real_inode = node
            .first_inode
            .lock()
            .unwrap()
            .inode
            .load(Ordering::Relaxed);
        layer.link(ctx, real_inode, real_parent_inode, name)?;

        newpnode.loaded.store(false, Ordering::Relaxed);
        let node = self.lookup_node(ctx, newparent, name)?;
        newpnode.loaded.store(true, Ordering::Relaxed);

        Ok(Entry {
            inode: node.inode,
            generation: 0,
            attr: node.stat64(ctx)?,
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    fn symlink(&self, ctx: &Context, linkname: &CStr, parent: Inode, name: &CStr) -> Result<Entry> {
        // soft link
        let empty_name = CString::new("").expect("invalid c string");
        let sname = name.to_string_lossy().into_owned().to_owned();

        let pnode = self.lookup_node(ctx, parent, empty_name.as_c_str())?;

        if pnode.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let node = self.lookup_node_ignore_enoent(ctx, parent, name)?;
        if let Some(n) = node {
            if !n.whiteout.load(Ordering::Relaxed) {
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }

            // whiteout, may need to delete it
            self.delete_whiteout_node(ctx, Arc::clone(&n))?;

            // delete from hash
            self.inodes.lock().unwrap().remove(&n.inode);
            pnode.childrens.lock().unwrap().remove(sname.as_str());
        }

        let pnode = self.copy_node_up(ctx, Arc::clone(&pnode))?;
        // find out layer, real parent..
        let (layer, real_parent) = {
            let first = pnode.first_inode.lock().unwrap();
            (
                Arc::clone(first.layer.as_ref().unwrap()),
                first.inode.load(Ordering::Relaxed),
            )
        };

        layer.symlink(ctx, linkname, real_parent, name)?;

        pnode.loaded.store(false, Ordering::Relaxed);
        let node = self.lookup_node(ctx, parent, name)?;
        pnode.loaded.store(true, Ordering::Relaxed);

        Ok(Entry {
            inode: node.inode,
            generation: 0,
            attr: node.stat64(ctx)?,
            attr_flags: 0,
            attr_timeout: self.config.attr_timeout,
            entry_timeout: self.config.entry_timeout,
        })
    }

    fn readlink(&self, ctx: &Context, inode: Inode) -> Result<Vec<u8>> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        // find out real inode
        let (layer, real_inode) = {
            let first = node.first_inode.lock().unwrap();
            (
                Arc::clone(first.layer.as_ref().unwrap()),
                first.inode.load(Ordering::Relaxed),
            )
        };

        layer.readlink(ctx, real_inode)
    }

    fn flush(&self, ctx: &Context, inode: Inode, handle: Handle, lock_owner: u64) -> Result<()> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

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
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // in lower layer, error out or just success?
            // FIXME:
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;

        // FIXME: need to test if inode matches corresponding handle?

        layer.fsync(ctx, real_inode, datasync, real_handle)
    }

    fn fsyncdir(&self, ctx: &Context, inode: Inode, datasync: bool, handle: Handle) -> Result<()> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // in lower layer, error out or just success?
            // FIXME:
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;

        // FIXME: need to test if inode matches corresponding handle?

        layer.fsyncdir(ctx, real_inode, datasync, real_handle)
    }

    fn access(&self, ctx: &Context, inode: Inode, mask: u32) -> Result<()> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

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
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // copy node into upper layer
            // FIXME:
            self.copy_node_up(ctx, Arc::clone(&node))?;
        }

        let _node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

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
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.getxattr(ctx, real_inode, name, size)
    }

    fn listxattr(&self, ctx: &Context, inode: Inode, size: u32) -> Result<ListxattrReply> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let (layer, real_inode) = self.find_real_inode(ctx, inode)?;

        layer.listxattr(ctx, real_inode, size)
    }

    fn removexattr(&self, ctx: &Context, inode: Inode, name: &CStr) -> Result<()> {
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // copy node into upper layer
            // FIXME:
            self.copy_node_up(ctx, Arc::clone(&node))?;
        }

        let _node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

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
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        if !self.node_in_upper_layer(Arc::clone(&node))? {
            // copy node into upper layer
            // FIXME:
            // only for node in upper layer, not in upper layer
            // indicates open in readonly mode, and cannot fallocate
            return Err(Error::from_raw_os_error(libc::EPERM));
        }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;

        layer.fallocate(ctx, real_inode, real_handle, mode, offset, length)
    }

    fn lseek(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> Result<u64> {
        // can this be on dir? FIXME: assume file for now
        // we need special process if it can be called on dir
        let empty_name = CString::new("").expect("invalid c string");
        let node = self.lookup_node(ctx, inode, empty_name.as_c_str())?;

        if node.whiteout.load(Ordering::Relaxed) {
            return Err(Error::from_raw_os_error(libc::ENOENT));
        }

        let st = node.stat64(ctx)?;
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            error!("lseek on directory");
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        let (layer, real_inode, real_handle) = self.find_real_info_from_handle(ctx, handle)?;
        layer.lseek(ctx, real_inode, real_handle, offset, whence)
    }
}

// impl BackendFileSystem for OverlayFs {
//     fn mount(&self) -> Result<(Entry, u64)> {
//         if let Some(ref root) = self.root.as_ref() {
//             let ctx = Context::default();
//             Ok((
//                 Entry {
//                     inode: root.inode,
//                     generation: 0,
//                     attr: root.stat64(&ctx)?,
//                     attr_flags: 0,
//                     attr_timeout: self.config.attr_timeout,
//                     entry_timeout: self.config.entry_timeout,
//                 },
//                 VFS_MAX_INO,
//             ))
//         } else {
//             Err(Error::new(ErrorKind::Other, "fs not inited"))
//         }
//     }

//     fn as_any(&self) -> &dyn Any {
//         self
//     }
// }
