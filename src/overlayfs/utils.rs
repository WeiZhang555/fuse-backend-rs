use crate::abi::fuse_abi::stat64;
use libc;
use std::ffi::CString;
use std::io::{self, Error, Result};

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
    CString::new(name).map_err(|e| Error::new(io::ErrorKind::InvalidData, e))
}
