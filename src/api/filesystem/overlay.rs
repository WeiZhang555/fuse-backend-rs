// Copyright (C) 2023 Ant Group. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

#![allow(missing_docs)]

use crate::abi::fuse_abi::stat64;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};

use super::{Context, Entry, FileSystem, GetxattrReply};

pub const OPAQUE_XATTR_LEN: u32 = 16;
pub const OPAQUE_XATTR: &str = "user.fuseoverlayfs.opaque";
pub const UNPRIVILEGED_OPAQUE_XATTR: &str = "user.overlay.opaque";
pub const PRIVILEGED_OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// A filesystem must implement Layer trait, or it cannot be used as an OverlayFS layer.
pub trait Layer: FileSystem {
    /// Return the root inode number
    fn root_inode(&self) -> Self::Inode;

    /// Create whiteout file with name <name>.
    #[allow(clippy::unnecessary_cast)]
    fn create_whiteout(&self, ctx: &Context, parent: Self::Inode, name: &CStr) -> Result<Entry> {
        // Use temp value to avoid moved 'parent'.
        let ino: u64 = parent.into();
        match self.lookup(ctx, ino.into(), name) {
            Ok(v) => {
                if v.inode != 0 {
                    // Decrease the refcount.
                    self.forget(ctx, v.inode.into(), 1);
                }

                // Find whiteout char dev.
                if is_whiteout(v.attr) {
                    return Ok(v);
                }
                // Negative entry with inode 0 indicates no entry.
                if v.inode != 0 {
                    // File exists with same name, create whiteout file is not allowed.
                    return Err(Error::from_raw_os_error(libc::EEXIST));
                }
            }
            Err(e) => match e.raw_os_error() {
                Some(raw_error) => {
                    // We expect ENOENT or ENAMETOOLONG error.
                    if raw_error != libc::ENOENT {
                        return Err(e);
                    }
                }
                None => return Err(e),
            },
        }

        // Try to create whiteout char device with 0/0 device number.
        let dev = libc::makedev(0, 0);
        let mode = libc::S_IFCHR | 0o777;
        self.mknod(ctx, ino.into(), name, mode as u32, dev as u32, 0)
    }

    /// Delete whiteout file with name <name>.
    fn delete_whiteout(&self, ctx: &Context, parent: Self::Inode, name: &CStr) -> Result<()> {
        // Use temp value to avoid moved 'parent'.
        let ino: u64 = parent.into();
        match self.lookup(ctx, ino.into(), name) {
            Ok(v) => {
                if v.inode != 0 {
                    // Decrease the refcount.
                    self.forget(ctx, v.inode.into(), 1);
                }

                // Find whiteout so we can safely delete it.
                if is_whiteout(v.attr) {
                    return self.unlink(ctx, ino.into(), name);
                }
                // Negative entry with inode 0 indicates no entry.
                if v.inode != 0 {
                    // File exists but not whiteout file.
                    return Err(Error::from_raw_os_error(libc::EINVAL));
                }
            }
            Err(e) => match e.raw_os_error() {
                Some(raw_error) => {
                    // ENOENT and ENAMETOOLONG are good.
                    if raw_error != libc::ENOENT {
                        return Err(e);
                    }
                }
                None => return Err(e),
            },
        }
        Ok(())
    }

    /// Check if the Inode is a whiteout file
    fn is_whiteout(&self, ctx: &Context, inode: Self::Inode) -> Result<bool> {
        let (st, _) = self.getattr(ctx, inode, None)?;

        // Check attributes of the inode to see if it's a whiteout char device.
        Ok(is_whiteout(st))
    }

    fn set_opaque(&self, ctx: &Context, inode: Self::Inode) -> Result<()> {
        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        // See ref: https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories
        self.setxattr(ctx, inode, to_cstring(OPAQUE_XATTR)?.as_c_str(), b"y", 0)
    }

    // Check if the directory is opaque.
    fn is_opaque(&self, ctx: &Context, inode: Self::Inode) -> Result<bool> {
        // Use temp value to avoid moved 'parent'.
        let ino: u64 = inode.into();

        // Get attributes of the directory.
        let (st, _d) = self.getattr(ctx, ino.into(), None)?;
        if !is_dir(st) {
            return Err(Error::from_raw_os_error(libc::ENOTDIR));
        }

        // Return Result<(is_opaque, break)>, if 'break' is true, stop and return the is_opaque value.
        let check_attr =
            |inode: Self::Inode, attr_name: &str, attr_size: u32| -> Result<(bool, bool)> {
                // TODO: map error?
                let cname = CString::new(attr_name)?;
                match self.getxattr(ctx, inode, cname.as_c_str(), attr_size) {
                    Ok(v) => {
                        // xattr name exists and we get value.
                        if let GetxattrReply::Value(buf) = v {
                            if buf.len() == 1 && buf[0].to_ascii_lowercase() == b'y' {
                                return Ok((true, true));
                            }
                        }
                        // no value found, go on to next check.
                        Ok((false, false))
                    }
                    Err(e) => {
                        if let Some(raw_error) = e.raw_os_error() {
                            // Overlay rely on getxattr, so if getxattr is not supported, we needs to error out.
                            // if raw_error == libc::ENOTSUP
                            //     || raw_error == libc::ENOSYS
                            // {
                            //     return Ok((false, true));
                            // }

                            if raw_error == libc::ENODATA {
                                return Ok((false, false));
                            }
                        }

                        Err(e)
                    }
                }
            };

        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        // See ref: https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories
        let (is_opaque, stop) = check_attr(ino.into(), PRIVILEGED_OPAQUE_XATTR, OPAQUE_XATTR_LEN)?;
        if stop {
            return Ok(is_opaque);
        }

        // Also check for the unprivileged version of the xattr.
        let (is_opaque, stop) =
            check_attr(ino.into(), UNPRIVILEGED_OPAQUE_XATTR, OPAQUE_XATTR_LEN)?;
        if stop {
            return Ok(is_opaque);
        }

        // And our customized version of the xattr.
        let (is_opaque, stop) = check_attr(ino.into(), OPAQUE_XATTR, OPAQUE_XATTR_LEN)?;
        if stop {
            return Ok(is_opaque);
        }

        Ok(false)
    }
}

pub(crate) fn is_dir(st: stat64) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub(crate) fn is_chardev(st: stat64) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFCHR
}

pub(crate) fn is_whiteout(st: stat64) -> bool {
    // A whiteout is created as a character device with 0/0 device number.
    // See ref: https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories
    let major = unsafe { libc::major(st.st_rdev) };
    let minor = unsafe { libc::minor(st.st_rdev) };
    is_chardev(st) && major == 0 && minor == 0
}

pub(crate) fn to_cstring(name: &str) -> Result<CString> {
    CString::new(name).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}
