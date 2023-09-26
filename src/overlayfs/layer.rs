#![allow(missing_docs)]

use super::*;
use libc;
use std::ffi::CString;
use std::io::{self, Error, Result};

use crate::api::filesystem::{Context, Entry, FileSystem, GetxattrReply};

pub const OPAQUE_XATTR_LEN: u32 = 16;

type BoxedFileSystem = Box<dyn FileSystem<Inode = Inode, Handle = Handle> + Send + Sync>;

pub struct Layer {
    fs: Arc<BoxedFileSystem>,
    is_upper: bool,
}

// we cannot constraint Layer with Eq, as Eq requires Sized
// So we need api to get an identifier and then use identifier
// to do comparation.. Here may have better solutions..
impl Layer {
    pub fn new(fs: BoxedFileSystem, is_upper: bool) -> Self {
        Layer {
            fs: Arc::new(fs),
            is_upper,
        }
    }

    pub(crate) fn is_upper(&self) -> bool {
        self.is_upper
    }

    pub(crate) fn fs(&self) -> Arc<BoxedFileSystem> {
        self.fs.clone()
    }

    // file exists, returns true, not exists return false
    // otherwise, error out
    // Ok(None) denotes no entry
    pub(crate) fn lookup_ignore_enoent(
        &self,
        ctx: &Context,
        ino: u64,
        name: &str,
    ) -> Result<Option<Entry>> {
        let cname = CString::new(name).map_err(|e| Error::new(io::ErrorKind::InvalidData, e))?;

        match self.fs.lookup(ctx, ino, cname.as_c_str()) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::ENOENT || raw_error == libc::ENAMETOOLONG {
                        return Ok(None);
                    }
                }

                return Err(e);
            }
        }
    }

    pub(crate) fn getxattr_ignore_nodata(
        &self,
        ctx: &Context,
        inode: u64,
        name: &str,
        size: u32,
    ) -> Result<Option<Vec<u8>>> {
        // TODO: map error?
        let cname = CString::new(name)?;
        match self.fs.getxattr(ctx, inode, cname.as_c_str(), size) {
            Ok(v) => {
                // xattr name exists and we get value.
                if let GetxattrReply::Value(buf) = v {
                    return Ok(Some(buf));
                }
                // no value found.
                return Ok(None);
            }
            Err(e) => {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::ENODATA
                        || raw_error == libc::ENOTSUP
                        || raw_error == libc::ENOSYS
                    {
                        return Ok(None);
                    }
                }

                return Err(e);
            }
        }
    }

    // Check is the inode is a whiteout.
    pub(crate) fn is_whiteout(&self, ctx: &Context, inode: u64) -> Result<bool> {
        let (st, _) = self.fs().getattr(ctx, inode, None)?;

        // Check attributes of the inode to see if it's a whiteout char device.
        Ok(utils::is_whiteout(st))
    }

    // Check if the directory is opaque.
    pub(crate) fn is_opaque_whiteout(&self, ctx: &Context, inode: u64) -> Result<bool> {
        // Get attributes of the directory.
        let (st, _d) = self.fs().getattr(ctx, inode, None)?;
        if !utils::is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        // See ref: https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories
        if let Some(v) =
            self.getxattr_ignore_nodata(ctx, inode, PRIVILEGED_OPAQUE_XATTR, OPAQUE_XATTR_LEN)?
        {
            if v[0].to_ascii_lowercase() == b'y' {
                return Ok(true);
            }
            return Ok(false);
        }

        // Also check for the unprivileged version of the xattr.
        if let Some(v) =
            self.getxattr_ignore_nodata(ctx, inode, UNPRIVILEGED_OPAQUE_XATTR, OPAQUE_XATTR_LEN)?
        {
            if v[0].to_ascii_lowercase() == b'y' {
                return Ok(true);
            }
            return Ok(false);
        }

        // And our customized version of the xattr.
        if let Some(v) = self.getxattr_ignore_nodata(ctx, inode, OPAQUE_XATTR, OPAQUE_XATTR_LEN)? {
            if v[0].to_ascii_lowercase() == b'y' {
                return Ok(true);
            }
            return Ok(false);
        }

        Ok(false)
    }

    pub(crate) fn delete_whiteout(&self, ctx: &Context, parent: u64, name: &str) -> Result<()> {
        if !self.is_upper() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // Delete whiteout char dev with 0/0 device number.
        if let Some(st) = self.lookup_ignore_enoent(ctx, parent, name)? {
            if utils::is_whiteout(st.attr) {
                self.fs
                    .unlink(ctx, parent, utils::to_cstring(name)?.as_c_str())?;
            }
        }

        Ok(())
    }

    pub(crate) fn create_whiteout(&self, ctx: &Context, parent: u64, name: &str) -> Result<Entry> {
        if !self.is_upper() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        let entry = self.lookup_ignore_enoent(ctx, parent, name)?;
        match entry {
            Some(v) => {
                // Find whiteout char dev.
                if utils::is_whiteout(v.attr) {
                    return Ok(v);
                }
                // File exists with same name, create is not allowed.
                return Err(Error::from_raw_os_error(libc::EEXIST));
            }
            // Continue the creation if whiteout file doesn't exist.
            None => {}
        }

        // Try to create whiteout char device with 0/0 device number.
        let dev = libc::makedev(0, 0);
        let mode = libc::S_IFCHR | 0o777;
        self.fs.mknod(
            ctx,
            parent,
            utils::to_cstring(name)?.as_c_str(),
            mode,
            dev as u32,
            0,
        )
    }

    pub(crate) fn create_opaque_whiteout(&self, ctx: &Context, inode: u64) -> Result<()> {
        if !self.is_upper() {
            return Err(Error::from_raw_os_error(libc::EROFS));
        }

        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        // See ref: https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories

        self.fs.setxattr(
            ctx,
            inode,
            utils::to_cstring(OPAQUE_XATTR)?.as_c_str(),
            b"y",
            0,
        )
    }
}
