extern crate fuse_backend_rs;
extern crate lazy_static;
extern crate libc;
extern crate log;
extern crate signal_hook;
extern crate simple_logger;
extern crate vmm_sys_util;

use std::env;
use std::io::{Error, Result};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use fuse_backend_rs::api::filesystem::Layer;
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::overlayfs::config::Config;
use fuse_backend_rs::overlayfs::OverlayFs;
use fuse_backend_rs::passthrough::{self, PassthroughFs};
use fuse_backend_rs::transport::{FuseChannel, FuseSession};
use log::LevelFilter;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};
use simple_logger::SimpleLogger;

#[derive(Debug, Default)]
pub struct Args {
    name: String,
    mountpoint: String,
    lowerdir: Vec<String>,
    upperdir: String,
    workdir: String,
}

pub struct FuseServer {
    server: Arc<Server<Arc<OverlayFs>>>,
    ch: FuseChannel,
}

type BoxedLayer = Box<dyn Layer<Inode = u64, Handle = u64> + Send + Sync>;

fn new_passthroughfs_layer(rootdir: &str) -> Result<BoxedLayer> {
    let mut config = passthrough::Config::default();
    config.root_dir = String::from(rootdir);
    // enable xattr
    config.xattr = true;
    config.do_import = true;
    let fs = Box::new(PassthroughFs::<()>::new(config)?);
    fs.import()?;
    Ok(fs as BoxedLayer)
}

fn help() {
    println!(
        "Usage:\n   testoverlay -o lowerdir=<lower1>:<lower2>:<more>,upperdir=<upper>,workdir=<work> <name> <mountpoint>\n"
    );
}

fn parse_args() -> Result<Args> {
    let args = env::args().collect::<Vec<String>>();
    if args.len() < 5 {
        help();
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }

    if args[1].as_str() != "-o" {
        help();
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }

    let mut cmd_args = Args {
        name: args[3].clone(),
        mountpoint: args[4].clone(),
        ..Default::default()
    };
    let option = args[2].clone();
    // Parse option.
    option.split(",").try_for_each(|value| -> Result<()> {
        let kv = value.split("=").collect::<Vec<&str>>();
        if kv.len() != 2 {
            println!("invalid option: {}", value);
            help();
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        match kv[0] {
            "lowerdir" => {
                cmd_args.lowerdir = kv[1]
                    .split(":")
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>();
            }
            "upperdir" => {
                cmd_args.upperdir = kv[1].to_string();
            }
            "workdir" => {
                cmd_args.workdir = kv[1].to_string();
            }
            _ => {
                println!("invalid option: {}", kv[0]);
                help();
                return Err(Error::from_raw_os_error(libc::EINVAL));
            }
        }
        Ok(())
    })?;

    // All fields should be set.
    if cmd_args.lowerdir.is_empty() || cmd_args.upperdir.is_empty() || cmd_args.workdir.is_empty() {
        println!("lowerdir, upperdir and workdir should be set");
        help();
        return Err(Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(cmd_args)
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .init()
        .unwrap();
    let args = parse_args()?;
    println!("args: {:?}", args);

    // let basedir = "/home/zhangwei/program/test-overlay/test2/";
    let upper_layer = Arc::new(new_passthroughfs_layer(&args.upperdir)?);
    let mut lower_layers = Vec::new();
    for lower in args.lowerdir {
        lower_layers.push(Arc::new(new_passthroughfs_layer(&lower)?));
    }

    let mut config = Config::default();
    config.work = args.workdir.clone();
    config.mountpoint = args.mountpoint.clone();
    config.do_import = true;

    print!("new overlay fs\n");
    let mut fs = OverlayFs::new(Some(upper_layer), lower_layers, config)?;
    print!("init root inode\n");
    fs.init_root()?;

    print!("open fuse session\n");
    let mut se = FuseSession::new(Path::new(&args.mountpoint), &args.name, "", false).unwrap();
    print!("session opened\n");
    se.mount().unwrap();

    let mut server = FuseServer {
        server: Arc::new(Server::new(Arc::new(fs))),
        ch: se.new_channel().unwrap(),
    };

    let handle = thread::spawn(move || {
        let _ = server.svc_loop();
    });

    // main thread
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    for _sig in signals.forever() {
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
