//! Real FUSE request/reply frames over a socket, without a kernel mount.
//!
//! Exercise the production trait callbacks and signed continuation boundary.
//! These are not evidence for the separate generic/310 concurrency hang.

use super::*;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

const LAST_COOKIE: u64 = u64::MAX >> 1;
const READDIR: u32 = 28;
const READDIRPLUS: u32 = 44;

struct CookieFs {
    entries: Vec<FfsDirEntry>,
    offsets: Arc<Mutex<Vec<u64>>>,
}

impl FsOps for CookieFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        Ok(InodeAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: if ino.0 == 1 {
                FfsFileType::Directory
            } else {
                FfsFileType::RegularFile
            },
            perm: 0o755,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            generation: 7,
        })
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        unreachable!("directory wire fixture does not look up names")
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        assert_eq!(ino, InodeNumber(1));
        self.offsets.lock().unwrap().push(offset);
        Ok(ReaddirPage::new(
            self.entries
                .iter()
                .filter(|entry| entry.offset > offset)
                .cloned()
                .collect(),
        ))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        unreachable!("directory wire fixture does not read file data")
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        unreachable!("directory wire fixture does not read symlinks")
    }
}

struct Wire {
    stream: UnixStream,
    unique: u64,
    handle: u64,
}

struct Response {
    error: i32,
    body: Vec<u8>,
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl Wire {
    fn request(&mut self, opcode: u32, body: &[u8]) -> Response {
        self.unique += 1;
        let mut packet = vec![0; 40 + body.len()];
        let length = u32::try_from(packet.len()).unwrap();
        packet[..4].copy_from_slice(&length.to_ne_bytes());
        packet[4..8].copy_from_slice(&opcode.to_ne_bytes());
        packet[8..16].copy_from_slice(&self.unique.to_ne_bytes());
        packet[16..24].copy_from_slice(&1_u64.to_ne_bytes());
        packet[40..].copy_from_slice(body);
        self.stream.write_all(&packet).unwrap();
        let mut header = [0; 16];
        self.stream.read_exact(&mut header).unwrap();
        let length = usize::try_from(u32::from_ne_bytes(header[..4].try_into().unwrap())).unwrap();
        assert!((16..=8192).contains(&length), "bounded FUSE reply");
        assert_eq!(u64_at(&header, 8), self.unique, "one reply per request");
        let error = i32::from_ne_bytes(header[4..8].try_into().unwrap());
        let mut body = vec![0; length - 16];
        self.stream.read_exact(&mut body).unwrap();
        Response { error, body }
    }

    fn initialize(&mut self) {
        let flags =
            u32::try_from(fuse_consts::FUSE_DO_READDIRPLUS | fuse_consts::FUSE_READDIRPLUS_AUTO)
                .unwrap();
        let body: Vec<_> = [7_u32, 31, 4096, flags]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect();
        let initialized = self.request(26, &body);
        assert_eq!(initialized.error, 0);
        assert_eq!(
            u32::from_ne_bytes(initialized.body[..4].try_into().unwrap()),
            7
        );
        let opened = self.request(27, &[0; 8]);
        assert_eq!(opened.error, 0);
        self.handle = u64_at(&opened.body, 0);
        assert_ne!(self.handle, 0);
    }

    fn readdir(&mut self, opcode: u32, offset: i64, size: u32) -> Response {
        let mut body = [0; 40];
        body[..8].copy_from_slice(&self.handle.to_ne_bytes());
        body[8..16].copy_from_slice(&offset.to_ne_bytes());
        body[16..20].copy_from_slice(&size.to_ne_bytes());
        self.request(opcode, &body)
    }

    fn release(&mut self) {
        let mut body = [0; 24];
        body[..8].copy_from_slice(&self.handle.to_ne_bytes());
        let response = self.request(29, &body);
        assert_eq!(response.error, 0);
        assert_eq!(response.body.as_slice(), b"");
    }
}

fn with_directory(
    cookies: &[u64],
    run: impl FnOnce(&mut Wire, &LookupRefcounts, &Mutex<Vec<u64>>),
) {
    let offsets = Arc::new(Mutex::new(Vec::new()));
    let entries = cookies
        .iter()
        .enumerate()
        .map(|(index, &offset)| FfsDirEntry {
            ino: InodeNumber(u64::try_from(index).unwrap() + 2),
            offset,
            kind: FfsFileType::RegularFile,
            name: format!("f{index}").into_bytes(),
        })
        .collect();
    let fuse = FrankenFuse::new(Box::new(CookieFs {
        entries,
        offsets: Arc::clone(&offsets),
    }));
    let lookups = fuse.inner.lookup_refcounts.clone();
    std::thread::scope(|scope| {
        // The peer closes during assertion unwind before the scoped join, so
        // a failed reply assertion cannot strand the session's blocking read.
        let (device, stream) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut session =
            fuser::Session::from_fd(fuse, OwnedFd::from(device), fuser::SessionACL::All);
        let worker = scope.spawn(move || session.run());
        let mut wire = Wire {
            stream,
            unique: 0,
            handle: 0,
        };
        wire.initialize();
        run(&mut wire, &lookups, &offsets);
        wire.release();
        drop(wire);
        worker.join().unwrap().unwrap();
    });
}

fn entries(response: &Response, opcode: u32) -> Vec<(u64, u64, Vec<u8>)> {
    assert_eq!(response.error, 0);
    let mut result = Vec::new();
    let mut start = 0;
    while start < response.body.len() {
        // Linux fuse_entry_out precedes the same fuse_dirent in READDIRPLUS.
        let attr_bytes = if opcode == READDIRPLUS { 128 } else { 0 };
        let dirent = start + attr_bytes;
        let ino = u64_at(&response.body, dirent);
        let cookie = u64_at(&response.body, dirent + 8);
        let name_len = usize::try_from(u32::from_ne_bytes(
            response.body[dirent + 16..dirent + 20].try_into().unwrap(),
        ))
        .unwrap();
        let name_start = dirent + 24;
        let name = response.body[name_start..name_start + name_len].to_vec();
        if opcode == READDIRPLUS {
            assert_eq!(u64_at(&response.body, start), ino);
            assert_eq!(u64_at(&response.body, start + 8), 7);
        }
        result.push((ino, cookie, name));
        start = (name_start + name_len).next_multiple_of(8);
    }
    assert_eq!(start, response.body.len());
    result
}

#[test]
fn wire_directory_overflow_returns_errno_without_fabricated_entries_or_references() {
    for opcode in [READDIR, READDIRPLUS] {
        for cookie in [LAST_COOKIE + 1, u64::MAX] {
            with_directory(&[cookie], |wire, lookups, offsets| {
                for _ in 0..2 {
                    let response = wire.readdir(opcode, 0, 4096);
                    assert_eq!(response.error, -libc::EOVERFLOW);
                    assert_eq!(response.body.as_slice(), b"");
                    assert_eq!(lookups.count(2), 0);
                }
                assert_eq!(*offsets.lock().unwrap(), vec![0, 0]);
                let negative = wire.readdir(opcode, -1, 4096);
                assert_eq!(negative.error, -libc::EINVAL);
                assert_eq!(negative.body.as_slice(), b"");
                assert_eq!(*offsets.lock().unwrap(), vec![0, 0]);
            });
        }
    }
}

#[test]
fn wire_directory_valid_prefix_preserves_cookies_and_lookups_before_overflow() {
    for opcode in [READDIR, READDIRPLUS] {
        let one_entry = if opcode == READDIRPLUS { 160 } else { 32 };
        for size in [one_entry, 4096] {
            with_directory(
                &[1, LAST_COOKIE, LAST_COOKIE + 1, u64::MAX],
                |wire, lookups, offsets| {
                    let mut accepted = entries(&wire.readdir(opcode, 0, size), opcode);
                    if size == one_entry {
                        assert_eq!(accepted, vec![(2, 1, b"f0".to_vec())]);
                        accepted.extend(entries(&wire.readdir(opcode, 1, size), opcode));
                    }
                    assert_eq!(
                        accepted,
                        vec![(2, 1, b"f0".to_vec()), (3, LAST_COOKIE, b"f1".to_vec())]
                    );
                    for ino in [2, 3] {
                        assert_eq!(lookups.count(ino), u64::from(opcode == READDIRPLUS));
                    }
                    for _ in 0..2 {
                        let response = wire.readdir(opcode, i64::MAX, size);
                        assert_eq!(response.error, -libc::EOVERFLOW);
                        assert_eq!(response.body.as_slice(), b"");
                        assert_eq!(lookups.count(4), 0);
                        assert_eq!(lookups.count(5), 0);
                    }
                    let expected = if size == one_entry {
                        vec![0, 1, LAST_COOKIE, LAST_COOKIE]
                    } else {
                        vec![0, LAST_COOKIE, LAST_COOKIE]
                    };
                    assert_eq!(*offsets.lock().unwrap(), expected);
                },
            );
        }
    }
}

#[test]
fn wire_directory_maximum_signed_cookie_round_trips_to_real_eof() {
    for opcode in [READDIR, READDIRPLUS] {
        with_directory(&[LAST_COOKIE - 1, LAST_COOKIE], |wire, lookups, offsets| {
            assert_eq!(
                entries(&wire.readdir(opcode, 0, 4096), opcode),
                vec![
                    (2, LAST_COOKIE - 1, b"f0".to_vec()),
                    (3, LAST_COOKIE, b"f1".to_vec())
                ]
            );
            let eof = wire.readdir(opcode, i64::MAX, 4096);
            assert_eq!(eof.error, 0);
            assert_eq!(eof.body.as_slice(), b"");
            assert_eq!(*offsets.lock().unwrap(), vec![0, LAST_COOKIE]);
            for ino in [2, 3] {
                assert_eq!(lookups.count(ino), u64::from(opcode == READDIRPLUS));
            }
        });
    }
}
