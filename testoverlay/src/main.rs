extern crate fuse_backend_rs;
extern crate lazy_static;
extern crate libc;
extern crate log;
extern crate signal_hook;
extern crate simple_logger;
extern crate vmm_sys_util;

use std::io::Result;
use std::path::Path;
use std::sync::Arc;

use fuse_backend_rs::api::server::Server;
//use fuse_backend_rs::api::{Vfs, VfsOptions};
use fuse_backend_rs::overlayfs::config::Config;
use fuse_backend_rs::overlayfs::{layer::Layer, OverlayFs};
use fuse_backend_rs::passthrough::{self, PassthroughFs};
use fuse_backend_rs::transport::{FuseChannel, FuseSession};
use log::LevelFilter;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};
use simple_logger::SimpleLogger;
use std::thread;

pub struct FuseServer {
    server: Arc<Server<Arc<OverlayFs>>>,
    ch: FuseChannel,
}

fn new_passthroughfs_layer(rootdir: &str, is_upper: bool) -> Result<Layer> {
    let mut config = passthrough::Config::default();
    config.root_dir = String::from(rootdir);
    // enable xattr
    config.xattr = true;
    config.do_import = true;
    let fs = Box::new(PassthroughFs::<()>::new(config)?);
    fs.import()?;
    Ok(Layer::new(fs, is_upper))
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .unwrap();
    let basedir = "/home/zhangwei/program/test-overlay/test2/";
    let upper_layer = Arc::new(Box::new(new_passthroughfs_layer(
        format!("{}up", basedir).as_str(),
        true,
    )?));
    let mut lower_layers = Vec::new();
    lower_layers.push(Arc::new(Box::new(new_passthroughfs_layer(
        format!("{}3", basedir).as_str(),
        false,
    )?)));
    lower_layers.push(Arc::new(Box::new(new_passthroughfs_layer(
        format!("{}2", basedir).as_str(),
        false,
    )?)));
    lower_layers.push(Arc::new(Box::new(new_passthroughfs_layer(
        format!("{}1", basedir).as_str(),
        false,
    )?)));

    let workdir = format!("{}work", basedir);
    let mountpoint = format!("{}merged", basedir);

    let mut config = Config::default();
    config.work = workdir;
    config.mountpoint = String::from(mountpoint.as_str());
    config.do_import = true;

    print!("new overlay fs\n");
    let mut fs = OverlayFs::new(Some(upper_layer), lower_layers, config)?;
    //let mut fs = OverlayFs::new(None, lower_layers, config)?;
    print!("init root inode\n");
    fs.init_root()?;

    // let vfs = Vfs::new(VfsOptions {
    //	no_open: false,
    //	no_opendir: false,
    //	..Default::default()
    // });

    // vfs.mount(Box::new(fs), "/")?;
    print!("open fuse session\n");
    let mut se =
        FuseSession::new(Path::new(mountpoint.as_str()), "testoverlay", "", false).unwrap();
    print!("session opened\n");
    se.mount().unwrap();

    let mut server = FuseServer {
        server: Arc::new(Server::new(Arc::new(fs))),
        ch: se.new_channel().unwrap(),
    };

    // let quit = Arc::new(Mutex::new(false));
    // let quit1 = Arc::clone(&quit);

    let handle = thread::spawn(move || {
        let _ = server.svc_loop();
    });

    // main thread
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    for _sig in signals.forever() {
        // *quit.lock().unwrap() = true;
        break;
    }

    se.umount().unwrap();
    se.wake().unwrap();

    let _ = handle.join();

    Ok(())
}

impl FuseServer {
    pub fn svc_loop(&mut self) -> Result<()> {
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        print!("entering server loop\n");
        loop {
            if let Some((reader, writer)) = self
                .ch
                .get_request()
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
            {
                if let Err(e) = self
                    .server
                    .handle_message(reader, writer.into(), None, None)
                {
                    match e {
                        fuse_backend_rs::Error::EncodeMessage(_ebadf) => {
                            break;
                        }
                        _ => {
                            print!("Handling fuse message failed");
                            continue;
                        }
                    }
                }
            } else {
                print!("fuse server exits");
                break;
            }
        }
        Ok(())
    }
}
