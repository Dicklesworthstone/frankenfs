//! Native FFI bindings to libfuse.
//!
//! This is a small set of bindings that are required to mount/unmount FUSE filesystems and
//! open/close a fd to the FUSE kernel driver.

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use super::is_mounted;
use super::mount_options::{MountOption, option_to_string};
use libc::c_int;
use log::{debug, error};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{mem, ptr};

const FUSERMOUNT_BIN: &str = "fusermount";
const FUSERMOUNT3_BIN: &str = "fusermount3";
const FUSERMOUNT_COMM_ENV: &str = "_FUSE_COMMFD";

#[derive(Debug)]
struct AutoUnmountHelper {
    socket: Option<UnixStream>,
    child: Child,
}

impl AutoUnmountHelper {
    fn cancel_and_reap(&mut self) {
        // ECHILD can mean another reaper released the numeric PID. Never
        // signal a cached PID/group after losing the child ownership witness.
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(_)) => return,
            Err(error) => {
                error!("auto-unmount helper ownership check failed: {error}");
                return;
            }
        }
        // fusermount's daemon calls setsid; include its namespace-check child.
        // Before setsid this group does not exist, so kill the owned PID too.
        if let Ok(pid) = libc::pid_t::try_from(self.child.id()) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        if let Err(error) = self.child.kill() {
            debug!("auto-unmount helper cancellation: {error}");
        }
        if let Err(error) = self.child.wait() {
            error!("auto-unmount helper reap failed: {error}");
        }
    }

    fn finish(&mut self, timeout: Duration) -> io::Result<()> {
        let started = Instant::now();
        drop(self.socket.take());
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(Error::other(format!(
                            "auto-unmount helper failed: {status}"
                        )))
                    };
                }
                Ok(None) => {
                    let remaining = timeout.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        self.cancel_and_reap();
                        return Err(Error::new(
                            ErrorKind::TimedOut,
                            "auto-unmount helper did not finish",
                        ));
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Debug)]
struct ReadOnlyUnmountView {
    mountinfo: File,
    encoded_path: Vec<u8>,
}

impl ReadOnlyUnmountView {
    fn new(path: &Path) -> io::Result<Self> {
        let mut encoded_path = Vec::new();
        for byte in path.as_os_str().as_bytes() {
            match byte {
                b'\t' => encoded_path.extend_from_slice(b"\\011"),
                b'\n' => encoded_path.extend_from_slice(b"\\012"),
                b' ' => encoded_path.extend_from_slice(b"\\040"),
                b'\\' => encoded_path.extend_from_slice(b"\\134"),
                byte => encoded_path.push(*byte),
            }
        }
        Ok(Self {
            mountinfo: File::open("/proc/thread-self/mountinfo")?,
            encoded_path,
        })
    }

    fn confirm_detached(&mut self, helper_pid: u32) -> io::Result<()> {
        self.mountinfo.seek(SeekFrom::Start(0))?;
        let mut records = Vec::new();
        self.mountinfo.read_to_end(&mut records)?;
        if records.iter().all(|byte| *byte == b'\n') {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "empty mountinfo after auto-unmount",
            ));
        }
        for record in records
            .split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
        {
            let fields: Vec<_> = record.split(|byte| *byte == b' ').collect();
            if fields.len() < 10 || !fields[4].starts_with(b"/") {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid mountinfo after auto-unmount",
                ));
            }
            if fields[4] == self.encoded_path.as_slice() {
                return Err(Error::other(format!(
                    "auto-unmount helper exited but mountpoint remains mounted (helper pid={helper_pid})"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Mount {
    mountpoint: CString,
    auto_unmount_socket: Option<AutoUnmountHelper>,
    fuse_device: Option<Arc<File>>,
    read_only_view: Option<ReadOnlyUnmountView>,
}
impl Mount {
    pub fn new(mountpoint: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mountpoint = mountpoint.canonicalize()?;
        // Capture only the namespace/root view, before creating the mount.
        // This holds no reference to the mounted FUSE root.
        let read_only_view = if read_only_auto_unmount(options) {
            Some(ReadOnlyUnmountView::new(&mountpoint)?)
        } else {
            None
        };
        let (file, sock) = fuse_mount_pure(mountpoint.as_os_str(), options)?;
        let file = Arc::new(file);
        Ok((
            file.clone(),
            Mount {
                mountpoint: CString::new(mountpoint.as_os_str().as_bytes())?,
                auto_unmount_socket: sock,
                fuse_device: Some(file),
                read_only_view,
            },
        ))
    }

    pub(crate) fn can_close_read_only(&self) -> bool {
        self.read_only_view.is_some()
    }

    /// Dispatch and external notifier owners must retire before this call.
    #[cfg(target_os = "linux")]
    pub(crate) fn finish_read_only_auto_unmount(mut self, timeout: Duration) -> io::Result<()> {
        let started = Instant::now();
        if self.read_only_view.is_none() || self.auto_unmount_socket.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "read-only auto-unmount was not negotiated",
            ));
        }
        let device = self
            .fuse_device
            .take()
            .ok_or_else(|| Error::other("FUSE device already released"))?;
        match Arc::try_unwrap(device) {
            Ok(device) => drop(device),
            Err(device) => {
                drop(device);
                if let Some(mut helper) = self.auto_unmount_socket.take() {
                    helper.cancel_and_reap();
                }
                return Err(Error::new(
                    ErrorKind::WouldBlock,
                    "FUSE device still has external reply or notifier owners",
                ));
            }
        }
        // Last device close ends this proven read-only connection. Only then
        // may the existing crash helper inspect ENOTCONN and detach its mount.
        let mut helper = self.auto_unmount_socket.take().unwrap();
        let helper_pid = helper.child.id();
        helper.finish(timeout.saturating_sub(started.elapsed()))?;
        self.read_only_view
            .as_mut()
            .unwrap()
            .confirm_detached(helper_pid)
    }
}

fn read_only_auto_unmount(options: &[MountOption]) -> bool {
    cfg!(target_os = "linux")
        && options.contains(&MountOption::RO)
        && options.contains(&MountOption::AutoUnmount)
        && !options.contains(&MountOption::RW)
        && options.iter().all(|option| match option {
            MountOption::CUSTOM(value) => value
                .strip_prefix("max_read=")
                .is_some_and(|size| size.parse::<u32>().is_ok_and(|size| size > 0)),
            MountOption::FSName(value) | MountOption::Subtype(value) => {
                !value.chars().any(|byte| matches!(byte, ',' | '\\' | '\0'))
            }
            _ => true,
        })
}

impl Drop for Mount {
    fn drop(&mut self) {
        use std::io::ErrorKind::PermissionDenied;
        let Some(device) = self.fuse_device.as_ref() else {
            return;
        };
        if !is_mounted(device) {
            // If the filesystem has already been unmounted, avoid unmounting it again.
            // Unmounting it a second time could cause a race with a newly mounted filesystem
            // living at the same mountpoint
            return;
        }
        if let Some(mut helper) = mem::take(&mut self.auto_unmount_socket) {
            // The original connection may survive a lazy detach while another
            // filesystem occupies this path. Only the original auto-unmount
            // helper may clean it up; a pathname fallback can unmount its
            // replacement. A failed helper must remain a reported join failure.
            drop(helper.socket.take());
            return;
        }
        if let Err(err) = super::libc_umount(&self.mountpoint) {
            if err.kind() == PermissionDenied {
                // Linux always returns EPERM for non-root users.  We have to let the
                // library go through the setuid-root "fusermount -u" to unmount.
                fuse_unmount_pure(&self.mountpoint)
            } else {
                error!("Unmount failed: {}", err)
            }
        }
    }
}

fn fuse_mount_pure(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(File, Option<AutoUnmountHelper>), io::Error> {
    let block_backed = block_mount_requested(options);
    if block_backed && options.contains(&MountOption::AutoUnmount) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "fuseblk requires a direct mount; auto_unmount is not supported",
        ));
    }
    #[cfg(not(target_os = "linux"))]
    if block_backed {
        return Err(Error::new(ErrorKind::Unsupported, "fuseblk requires Linux"));
    }
    if options.contains(&MountOption::AutoUnmount) {
        // Auto unmount is only supported via fusermount
        return fuse_mount_fusermount(mountpoint, options);
    }

    let res = fuse_mount_sys(mountpoint, options)?;
    match res {
        Some(file) => Ok((file, None)),
        None if block_backed => Err(Error::new(
            ErrorKind::PermissionDenied,
            "fuseblk requires permission to mount the supplied block device; refusing ordinary FUSE fallback",
        )),
        _ => {
            // Retry
            fuse_mount_fusermount(mountpoint, options)
        }
    }
}

fn block_mount_requested(options: &[MountOption]) -> bool {
    options
        .iter()
        .any(|option| matches!(option, MountOption::CUSTOM(value) if value == "blkdev"))
}

#[cfg(target_os = "linux")]
fn kernel_filesystem_type(options: &[MountOption]) -> &'static str {
    if block_mount_requested(options) {
        "fuseblk"
    } else {
        "fuse"
    }
}

fn fuse_unmount_pure(mountpoint: &CStr) {
    #[cfg(target_os = "linux")]
    unsafe {
        let result = libc::umount2(mountpoint.as_ptr(), libc::MNT_DETACH);
        if result == 0 {
            return;
        }
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let result = libc::unmount(mountpoint.as_ptr(), libc::MNT_FORCE);
        if result == 0 {
            return;
        }
    }

    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    builder
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(OsStr::new(&mountpoint.to_string_lossy().into_owned()));

    if let Ok(output) = builder.output() {
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    }
}

fn detect_fusermount_bin() -> String {
    for name in [
        FUSERMOUNT3_BIN.to_string(),
        FUSERMOUNT_BIN.to_string(),
        format!("/bin/{FUSERMOUNT3_BIN}"),
        format!("/bin/{FUSERMOUNT_BIN}"),
    ]
    .iter()
    {
        if Command::new(name).arg("-h").output().is_ok() {
            return name.to_string();
        }
    }
    // Default to fusermount3
    FUSERMOUNT3_BIN.to_string()
}

fn receive_fusermount_message(socket: &UnixStream) -> Result<File, Error> {
    let mut io_vec_buf = [0u8];
    let mut io_vec = libc::iovec {
        iov_base: io_vec_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: io_vec_buf.len(),
    };
    let cmsg_buffer_len = unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as libc::c_uint) };
    let mut cmsg_buffer = vec![0u8; cmsg_buffer_len as usize];
    let mut message: libc::msghdr;
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    {
        message = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut io_vec,
            msg_iovlen: 1,
            msg_control: cmsg_buffer.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len(),
            msg_flags: 0,
        };
    }
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    {
        message = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        message.msg_name = ptr::null_mut();
        message.msg_namelen = 0;
        message.msg_iov = &mut io_vec;
        message.msg_iovlen = 1;
        message.msg_control = (&mut cmsg_buffer).as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = cmsg_buffer.len() as u32;
        message.msg_flags = 0;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        message = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut io_vec,
            msg_iovlen: 1,
            msg_control: (&mut cmsg_buffer).as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len() as u32,
            msg_flags: 0,
        };
    }

    let mut result;
    loop {
        unsafe {
            result = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
        }
        if result != -1 {
            break;
        }
        let err = Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
    if result == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Unexpected EOF reading from fusermount",
        ));
    }

    unsafe {
        let control_msg = libc::CMSG_FIRSTHDR(&message);
        if (*control_msg).cmsg_type != libc::SCM_RIGHTS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Unknown control message from fusermount: {}",
                    (*control_msg).cmsg_type
                ),
            ));
        }
        let fd_data = libc::CMSG_DATA(control_msg);

        let fd = *(fd_data as *const c_int);
        if fd < 0 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(File::from_raw_fd(fd))
        }
    }
}

fn fuse_mount_fusermount(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(File, Option<AutoUnmountHelper>), Error> {
    let (child_socket, receive_socket) = UnixStream::pair()?;

    unsafe {
        libc::fcntl(child_socket.as_raw_fd(), libc::F_SETFD, 0);
    }

    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    if !options.is_empty() {
        builder.arg("-o");
        let options_strs: Vec<String> = options.iter().map(option_to_string).collect();
        builder.arg(options_strs.join(","));
    }
    builder
        .arg("--")
        .arg(mountpoint)
        .env(FUSERMOUNT_COMM_ENV, child_socket.as_raw_fd().to_string());

    let mut fusermount_child = builder.spawn()?;

    drop(child_socket); // close socket in parent

    let file = match receive_fusermount_message(&receive_socket) {
        Ok(f) => f,
        Err(_) => {
            // Drop receive socket, since fusermount has exited with an error
            drop(receive_socket);
            let output = fusermount_child.wait_with_output().unwrap();
            let stderr_string = String::from_utf8_lossy(&output.stderr).to_string();
            return if stderr_string.contains("only allowed if 'user_allow_other' is set") {
                Err(io::Error::new(ErrorKind::PermissionDenied, stderr_string))
            } else {
                Err(io::Error::other(stderr_string))
            };
        }
    };
    if !options.contains(&MountOption::AutoUnmount) {
        // Only close the socket, if auto unmount is not set.
        // fusermount will keep running until the socket is closed, if auto unmount is set
        drop(receive_socket);
        let output = fusermount_child.wait_with_output()?;
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        }
        return Ok((file, None));
    } else {
        if let Some(mut stdout) = fusermount_child.stdout.take() {
            let stdout_fd = stdout.as_raw_fd();
            unsafe {
                let mut flags = libc::fcntl(stdout_fd, libc::F_GETFL, 0);
                flags |= libc::O_NONBLOCK;
                libc::fcntl(stdout_fd, libc::F_SETFL, flags);
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stdout.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
        if let Some(mut stderr) = fusermount_child.stderr.take() {
            let stderr_fd = stderr.as_raw_fd();
            unsafe {
                let mut flags = libc::fcntl(stderr_fd, libc::F_GETFL, 0);
                flags |= libc::O_NONBLOCK;
                libc::fcntl(stderr_fd, libc::F_SETFL, flags);
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stderr.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
    }

    unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }

    Ok((
        file,
        Some(AutoUnmountHelper {
            socket: Some(receive_socket),
            child: fusermount_child,
        }),
    ))
}

// If returned option is none. Then fusermount binary should be tried
fn fuse_mount_sys(mountpoint: &OsStr, options: &[MountOption]) -> Result<Option<File>, Error> {
    let fuse_device_name = "/dev/fuse";

    let mountpoint_mode = File::open(mountpoint)?.metadata()?.permissions().mode();

    // Auto unmount requests must be sent to fusermount binary
    assert!(!options.contains(&MountOption::AutoUnmount));

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(fuse_device_name)
    {
        Ok(file) => file,
        Err(error) => {
            if error.kind() == ErrorKind::NotFound {
                error!("{} not found. Try 'modprobe fuse'", fuse_device_name);
            }
            return Err(error);
        }
    };
    assert!(
        file.as_raw_fd() > 2,
        "Conflict with stdin/stdout/stderr. fd={}",
        file.as_raw_fd()
    );

    let mut mount_options = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        file.as_raw_fd(),
        mountpoint_mode,
        nix::unistd::getuid(),
        nix::unistd::getgid()
    );

    for option in options.iter().filter(|x| {
        option_group(x) == MountOptionGroup::KernelOption
            || (block_mount_requested(options) && matches!(x, MountOption::Subtype(_)))
    }) {
        mount_options.push(',');
        mount_options.push_str(&option_to_string(option));
    }

    let mut flags = 0;
    if !options.contains(&MountOption::Dev) {
        // Default to nodev
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NODEV;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NODEV;
        }
    }
    if !options.contains(&MountOption::Suid) {
        // Default to nosuid
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NOSUID;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NOSUID;
        }
    }
    for flag in options
        .iter()
        .filter(|x| option_group(x) == MountOptionGroup::KernelFlag)
    {
        flags |= option_to_flag(flag);
    }

    // Default name is "/dev/fuse", then use the subtype, and lastly prefer the name
    let mut source = fuse_device_name;
    if let Some(MountOption::Subtype(subtype)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::Subtype(_)))
    {
        source = subtype;
    }
    if let Some(MountOption::FSName(name)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::FSName(_)))
    {
        source = name;
    }

    let c_source = CString::new(source).unwrap();
    let c_mountpoint = CString::new(mountpoint.as_bytes()).unwrap();

    let result = unsafe {
        #[cfg(target_os = "linux")]
        {
            let c_options = CString::new(mount_options).unwrap();
            let c_type = CString::new(kernel_filesystem_type(options)).unwrap();
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                c_type.as_ptr(),
                flags,
                c_options.as_ptr() as *const libc::c_void,
            )
        }
        #[cfg(target_os = "macos")]
        {
            let mut c_options = CString::new(mount_options).unwrap();
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                flags,
                c_options.as_ptr() as *mut libc::c_void,
            )
        }
    };
    if result == -1 {
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            return Ok(None); // Retry with fusermount
        } else {
            return Err(Error::new(
                err.kind(),
                format!("Error calling mount() at {mountpoint:?}: {err}"),
            ));
        }
    }

    Ok(Some(file))
}

#[derive(PartialEq)]
pub enum MountOptionGroup {
    KernelOption,
    KernelFlag,
    Fusermount,
}

pub fn option_group(option: &MountOption) -> MountOptionGroup {
    match option {
        MountOption::FSName(_) => MountOptionGroup::Fusermount,
        MountOption::Subtype(_) => MountOptionGroup::Fusermount,
        MountOption::CUSTOM(value) if value == "blkdev" => MountOptionGroup::Fusermount,
        MountOption::CUSTOM(_) => MountOptionGroup::KernelOption,
        MountOption::AutoUnmount => MountOptionGroup::Fusermount,
        MountOption::AllowOther => MountOptionGroup::KernelOption,
        MountOption::Dev => MountOptionGroup::KernelFlag,
        MountOption::NoDev => MountOptionGroup::KernelFlag,
        MountOption::Suid => MountOptionGroup::KernelFlag,
        MountOption::NoSuid => MountOptionGroup::KernelFlag,
        MountOption::RO => MountOptionGroup::KernelFlag,
        MountOption::RW => MountOptionGroup::KernelFlag,
        MountOption::Exec => MountOptionGroup::KernelFlag,
        MountOption::NoExec => MountOptionGroup::KernelFlag,
        MountOption::Atime => MountOptionGroup::KernelFlag,
        MountOption::NoAtime => MountOptionGroup::KernelFlag,
        MountOption::DirSync => MountOptionGroup::KernelFlag,
        MountOption::Sync => MountOptionGroup::KernelFlag,
        MountOption::Async => MountOptionGroup::KernelFlag,
        MountOption::AllowRoot => MountOptionGroup::KernelOption,
        MountOption::DefaultPermissions => MountOptionGroup::KernelOption,
    }
}

#[cfg(target_os = "linux")]
pub fn option_to_flag(option: &MountOption) -> libc::c_ulong {
    match option {
        MountOption::Dev => 0, // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => libc::MS_NODEV,
        MountOption::Suid => 0,
        MountOption::NoSuid => libc::MS_NOSUID,
        MountOption::RW => 0,
        MountOption::RO => libc::MS_RDONLY,
        MountOption::Exec => 0,
        MountOption::NoExec => libc::MS_NOEXEC,
        MountOption::Atime => 0,
        MountOption::NoAtime => libc::MS_NOATIME,
        MountOption::Async => 0,
        MountOption::Sync => libc::MS_SYNCHRONOUS,
        MountOption::DirSync => libc::MS_DIRSYNC,
        _ => unreachable!(),
    }
}

#[cfg(target_os = "macos")]
pub fn option_to_flag(option: &MountOption) -> libc::c_int {
    match option {
        MountOption::Dev => 0, // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => libc::MNT_NODEV,
        MountOption::Suid => 0,
        MountOption::NoSuid => libc::MNT_NOSUID,
        MountOption::RW => 0,
        MountOption::RO => libc::MNT_RDONLY,
        MountOption::Exec => 0,
        MountOption::NoExec => libc::MNT_NOEXEC,
        MountOption::Atime => 0,
        MountOption::NoAtime => libc::MNT_NOATIME,
        MountOption::Async => 0,
        MountOption::Sync => libc::MNT_SYNCHRONOUS,
        _ => unreachable!(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod block_mount_tests {
    use super::*;

    #[test]
    fn read_only_auto_unmount_rejects_ambiguous_options() {
        let base = vec![MountOption::RO, MountOption::AutoUnmount];
        assert!(read_only_auto_unmount(&base));
        assert!(!read_only_auto_unmount(&[MountOption::RO]));
        assert!(!read_only_auto_unmount(&[MountOption::AutoUnmount]));
        for option in [
            MountOption::RW,
            MountOption::CUSTOM("rw".into()),
            MountOption::CUSTOM("max_read=4096,rw".into()),
            MountOption::CUSTOM("max_read=0".into()),
            MountOption::FSName("name,rw".into()),
            MountOption::Subtype("name\\,rw".into()),
            MountOption::FSName("name\0".into()),
        ] {
            let mut options = base.clone();
            options.push(option);
            assert!(!read_only_auto_unmount(&options));
        }
        let mut safe = base;
        safe.extend([
            MountOption::FSName("frankenfs".into()),
            MountOption::Subtype("ffs".into()),
            MountOption::CUSTOM("max_read=16777216".into()),
        ]);
        assert!(read_only_auto_unmount(&safe));
    }

    fn component_helper(program: &str, own_group: bool) -> AutoUnmountHelper {
        use std::os::fd::OwnedFd;
        use std::os::unix::process::CommandExt;
        let (socket, child_socket) = UnixStream::pair().unwrap();
        let mut command = Command::new(program);
        if own_group {
            command.process_group(0);
        }
        if program == "sleep" {
            command.arg("60");
        }
        let child = command
            .stdin(Stdio::from(OwnedFd::from(child_socket)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        AutoUnmountHelper {
            socket: Some(socket),
            child,
        }
    }

    #[test]
    fn read_only_helper_deadline_reaps_owned_process() {
        for own_group in [false, true] {
            let mut helper = component_helper("sleep", own_group);
            if own_group {
                assert_eq!(
                    unsafe { libc::getpgid(helper.child.id() as i32) },
                    helper.child.id() as i32
                );
            }
            let error = helper.finish(Duration::from_millis(20)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::TimedOut);
            assert!(
                helper.child.try_wait().unwrap().is_some(),
                "timed-out helper was not reaped (own_group={own_group})"
            );
        }
    }

    #[test]
    fn read_only_release_closes_device_and_rejects_external_owners() {
        use std::io::Read;
        use std::mem::ManuallyDrop;
        use std::os::fd::OwnedFd;
        let root = ManuallyDrop::new(tempfile::tempdir().unwrap());
        for retained in [false, true] {
            let (device, mut peer) = UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            let device = Arc::new(File::from(OwnedFd::from(device)));
            let external = retained.then(|| Arc::clone(&device));
            let helper = component_helper("cat", false);
            let mount = Mount {
                mountpoint: CString::new(root.path().as_os_str().as_bytes()).unwrap(),
                auto_unmount_socket: Some(helper),
                fuse_device: Some(device),
                read_only_view: Some(ReadOnlyUnmountView::new(root.path()).unwrap()),
            };
            let result = mount.finish_read_only_auto_unmount(Duration::from_secs(1));
            if retained {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::WouldBlock);
                assert!(external.as_ref().unwrap().metadata().is_ok());
                assert_eq!(
                    peer.read(&mut [0]).unwrap_err().kind(),
                    ErrorKind::WouldBlock
                );
            } else {
                result.unwrap();
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            }
        }
    }

    #[test]
    fn block_transport_requires_explicit_opt_in_not_a_source_label() {
        assert_eq!(kernel_filesystem_type(&[]), "fuse");
        let source = MountOption::FSName("/dev/loop7".to_owned());
        assert_eq!(kernel_filesystem_type(&[source.clone()]), "fuse");
        assert_eq!(
            kernel_filesystem_type(&[source, MountOption::CUSTOM("blkdev".to_owned())]),
            "fuseblk"
        );
        assert_eq!(
            kernel_filesystem_type(&[MountOption::CUSTOM("blksize=4096".to_owned())]),
            "fuse"
        );
    }

    #[test]
    fn block_marker_selects_transport_instead_of_becoming_a_kernel_parameter() {
        assert!(
            option_group(&MountOption::CUSTOM("blkdev".to_owned())) == MountOptionGroup::Fusermount
        );
        assert!(
            option_group(&MountOption::CUSTOM("max_read=4096".to_owned()))
                == MountOptionGroup::KernelOption
        );
    }

    #[test]
    fn block_transport_cannot_enter_the_auto_unmount_helper_path() {
        let error = fuse_mount_pure(
            OsStr::new("/nonexistent-fuseblk-test-mount"),
            &[
                MountOption::AutoUnmount,
                MountOption::CUSTOM("blkdev".to_owned()),
            ],
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
