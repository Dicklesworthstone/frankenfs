#![forbid(unsafe_code)]
//! Explicitly authorized, sidecar-protected FUSE mounts.
//!
//! All format reads go through the same admitted repair device. The ordinary
//! mount command is unchanged; this entry point never creates protection from
//! an unknown image or treats startup differences as repairable corruption.

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Parser;
use ffs_block::ByteDevice;
use ffs_core::{
    Ext4JournalReplayMode, FsFlavor, FsOps, OpenFs, OpenOptions, RequestScope, detect_filesystem,
};
use ffs_error::FfsError;
use ffs_fuse::{MountConfig, MountOptions, mount_managed};
use ffs_ondisk::EXT4_VALID_FS;
use ffs_repair::sidecar::live::SidecarImageDevice;
use ffs_types::{ByteOffset, InodeNumber};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Parser)]
#[command(
    name = "ffs-protected-mount",
    about = "Mount a clean image read-only with explicitly authorized RaptorQ read repair"
)]
struct Args {
    image: PathBuf,
    sidecar: PathBuf,
    /// Existing empty directory. Omit only with --check.
    #[arg(required_unless_present = "check")]
    mountpoint: Option<PathBuf>,
    #[command(flatten)]
    authority: Authority,
    /// Validate admission and filesystem opening without mounting or enabling writes.
    #[arg(long, conflicts_with = "mountpoint")]
    check: bool,
    /// Let other users access the mount, subject to normal file permissions.
    #[arg(long, conflicts_with = "check")]
    allow_other: bool,
}

#[derive(Debug, clap::Args)]
struct Authority {
    /// Confirm no kernel mount or other program will access this image.
    #[arg(long, required = true)]
    exclusive_image: bool,
    /// Authorize verified repair writes to the image, even on a read-only mount.
    #[arg(long, required = true)]
    allow_repair: bool,
}

/// The filesystem cannot write through this adapter. Read repair belongs to
/// the device itself and is permitted only by the explicit CLI authority.
#[derive(Debug)]
struct ProtectedReadOnly(Arc<SidecarImageDevice>);

impl ByteDevice for ProtectedReadOnly {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> ffs_error::Result<()> {
        self.0.read_exact_at(cx, offset, out)
    }

    fn write_all_at(&self, cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.0.sync(cx)
    }
}

struct Prepared {
    fs: Arc<OpenFs>,
    device: Arc<SidecarImageDevice>,
    filesystem: &'static str,
    mountpoint: Option<PathBuf>,
}

impl Prepared {
    fn finish(self, cx: &Cx) -> Result<()> {
        // Managed unmount can time out. Do NOT announce a clean shutdown or
        // release our final ownership while a dispatch thread still owns ops.
        let fs = Arc::try_unwrap(self.fs).map_err(|_| {
            anyhow::anyhow!("FUSE still owns the filesystem after unmount; shutdown is incomplete")
        })?;
        drop(fs);
        self.device.sync(cx).context("final protected-device sync")
    }
}

fn checked_paths(args: &Args) -> Result<(PathBuf, PathBuf, Option<PathBuf>)> {
    if !args.authority.exclusive_image || !args.authority.allow_repair {
        bail!("--exclusive-image and --allow-repair are required");
    }
    if args.check == args.mountpoint.is_some() {
        bail!("choose a mountpoint or --check, but not both");
    }
    let mountpoint = args
        .mountpoint
        .as_deref()
        .map(|path| -> Result<PathBuf> {
            let path = path.canonicalize().context("resolve mountpoint")?;
            if !path.is_dir() {
                bail!("mountpoint is not a directory");
            }
            if let Some(entry) = std::fs::read_dir(&path)?.next() {
                entry?;
                bail!("protected mount requires an empty mountpoint");
            }
            Ok(path)
        })
        .transpose()?;
    let image = args.image.canonicalize().context("resolve image")?;
    let sidecar = args.sidecar.canonicalize().context("resolve sidecar")?;
    if let Some(mountpoint) = &mountpoint
        && (image.starts_with(mountpoint) || sidecar.starts_with(mountpoint))
    {
        bail!("mountpoint would hide the image or repair archive");
    }
    Ok((image, sidecar, mountpoint))
}

fn clean_single_image(cx: &Cx, device: &dyn ByteDevice) -> Result<&'static str> {
    // Enough for either primary superblock, bounded independently of image
    // size. Read through protection, never through a second unverified opener.
    let len = usize::try_from(device.len_bytes().min(0x1_1000))?;
    let mut probe = vec![0; len];
    device.read_exact_at(cx, ByteOffset(0), &mut probe)?;
    match detect_filesystem(&probe).context("detect protected filesystem")? {
        FsFlavor::Ext4(sb) => {
            // RECOVER and the orphan/error states require filesystem recovery,
            // not RaptorQ rollback. The companion mount initially admits only
            // clean protection points; Skip below is never a dirty-mount bypass.
            if sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
                || sb.state != EXT4_VALID_FS
                || sb.last_orphan != 0
            {
                bail!("ext4 needs recovery; reconcile offline and create fresh protection");
            }
            Ok("ext4")
        }
        FsFlavor::Btrfs(sb) => {
            if sb.num_devices != 1 || sb.log_root != 0 {
                bail!("protected mount requires a clean single-device btrfs image");
            }
            Ok("btrfs")
        }
    }
}

fn prepare(cx: &Cx, args: &Args) -> Result<Prepared> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let (image, sidecar, mountpoint) = checked_paths(args)?;
    let device = Arc::new(
        SidecarImageDevice::open(cx, &image, &sidecar)
            .context("admit image and existing repair protection")?,
    );
    let filesystem = clean_single_image(cx, device.as_ref())?;
    let options = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
        ..OpenOptions::default()
    };
    let fs = OpenFs::from_device(
        cx,
        Box::new(ProtectedReadOnly(Arc::clone(&device))),
        &options,
    )
    .context("open filesystem through the protected device")?;
    // Exercise the actual FUSE root alias before exposing the mount.
    FsOps::getattr(&fs, cx, &mut RequestScope::empty(), InodeNumber(1))
        .context("read protected filesystem root")?;
    Ok(Prepared {
        fs: Arc::new(fs),
        device,
        filesystem,
        mountpoint,
    })
}

fn mount_options(args: &Args) -> MountOptions {
    MountOptions {
        read_only: true,
        allow_other: args.allow_other,
        auto_unmount: true,
        ..MountOptions::default()
    }
}

#[derive(Serialize)]
struct Status<'a> {
    event: &'a str,
    filesystem: &'a str,
    image_bytes: u64,
    read_only: bool,
    repair_writes_authorized: bool,
}

fn emit(event: &str, prepared: &Prepared) -> Result<()> {
    let status = Status {
        event,
        filesystem: prepared.filesystem,
        image_bytes: prepared.device.len_bytes(),
        read_only: true,
        repair_writes_authorized: true,
    };
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &status)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn run(args: &Args) -> Result<()> {
    let cx = Cx::for_request();
    let cancellation = cx.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let shutdown: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::new(Mutex::new(None));
    let signal_stopped = Arc::clone(&stopped);
    let signal_shutdown = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal_stopped.store(true, Ordering::Release);
        cancellation.set_cancel_requested(true);
        if let Ok(target) = signal_shutdown.lock()
            && let Some(flag) = target.as_ref()
        {
            flag.store(true, Ordering::Release);
        }
    })
    .context("install shutdown handler")?;

    let prepared = prepare(&cx, args)?;
    if args.check {
        emit("checked_not_mounted", &prepared)?;
        return prepared.finish(&cx);
    }
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let mountpoint = prepared.mountpoint.as_ref().context("missing mountpoint")?;
    let config = MountConfig {
        options: mount_options(args),
        ..MountConfig::default()
    };
    let handle = mount_managed(Box::new(Arc::clone(&prepared.fs)), mountpoint, &config)
        .context("mount protected filesystem")?;
    let flag = Arc::clone(handle.shutdown_flag());
    *shutdown
        .lock()
        .map_err(|_| anyhow::anyhow!("shutdown state poisoned"))? = Some(Arc::clone(&flag));
    if stopped.load(Ordering::Acquire) {
        flag.store(true, Ordering::Release);
    }
    let announce = emit("mounted", &prepared);
    if announce.is_err() {
        flag.store(true, Ordering::Release);
    }
    let _metrics = handle.wait();
    // Shutdown is not performed with the cancelled startup context. We own a
    // separate cleanup capability and retain the device until it completes.
    prepared.finish(&Cx::for_request())?;
    announce
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ffs-protected-mount: {error:#}");
            ExitCode::from(
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<FfsError>()
                        .is_some_and(|error| matches!(error, FfsError::Cancelled))
                }) {
                    130
                } else {
                    4
                },
            )
        }
    }
}

#[cfg(test)]
mod tests;
