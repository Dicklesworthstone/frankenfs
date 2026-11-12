#![no_main]

use ffs_btrfs::{
    build_chmod_command, build_chown_command, build_clone_command, build_link_command,
    build_mkdir_command, build_mkfifo_command, build_mkfile_command, build_mknod_command,
    build_mksock_command, build_removexattr_command, build_rename_command, build_rmdir_command,
    build_setxattr_command, build_snapshot_command, build_subvol_command, build_symlink_command,
    build_truncate_command, build_unlink_command, build_update_extent_command,
    build_utimes_command, build_write_command, parse_send_stream, SendAttr, SendCommand,
    SendStreamBuilder,
};
use libfuzzer_sys::fuzz_target;

fn bounded_path(data: &[u8], offset: usize, prefix: &[u8]) -> Vec<u8> {
    let len = data.get(offset).copied().unwrap_or(0) as usize % 64;
    let mut path = prefix.to_vec();
    for i in 0..len {
        let byte = data.get(offset + 1 + i).copied().unwrap_or(b'a');
        if byte == 0 || byte == b'/' {
            path.push(b'x');
        } else {
            path.push(byte);
        }
    }
    path
}

fn bounded_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = data.get(offset + i).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn bounded_i64(data: &[u8], offset: usize) -> i64 {
    let mut bytes = [0_u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = data.get(offset + i).copied().unwrap_or(0);
    }
    i64::from_le_bytes(bytes)
}

fn bounded_i32(data: &[u8], offset: usize) -> i32 {
    let mut bytes = [0_u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = data.get(offset + i).copied().unwrap_or(0);
    }
    i32::from_le_bytes(bytes)
}

fn bounded_uuid(data: &[u8], offset: usize) -> [u8; 16] {
    let mut uuid = [0_u8; 16];
    for (i, b) in uuid.iter_mut().enumerate() {
        *b = data.get(offset + i).copied().unwrap_or(0);
    }
    uuid
}

fn bounded_bytes(data: &[u8], offset: usize, max_len: usize) -> Vec<u8> {
    let len = data.get(offset).copied().unwrap_or(0) as usize % max_len.saturating_add(1);
    let mut buf = Vec::with_capacity(len);
    for i in 0..len {
        buf.push(data.get(offset + 1 + i).copied().unwrap_or(0));
    }
    buf
}

fn add_command(builder: &mut SendStreamBuilder, cmd: SendCommand, attrs: Vec<(SendAttr, Vec<u8>)>) {
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut builder = SendStreamBuilder::new();
    builder.write_header();

    let uuid = bounded_uuid(data, 0);
    let ctransid = bounded_u64(data, 16);

    let (cmd, attrs) = build_subvol_command(b"fuzz_subvol", &uuid, ctransid);
    add_command(&mut builder, cmd, attrs);

    let cmd_count = data.get(24).copied().unwrap_or(0) % 16;
    let mut offset = 25_usize;

    for _ in 0..cmd_count {
        let cmd_type = data.get(offset).copied().unwrap_or(0) % 20;
        offset += 1;

        match cmd_type {
            0 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/dir_");
                let ino = bounded_u64(data, offset + 65);
                let (cmd, attrs) = build_mkdir_command(&path, ino);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            1 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let ino = bounded_u64(data, offset + 65);
                let (cmd, attrs) = build_mkfile_command(&path, ino);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            2 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let file_offset = bounded_u64(data, offset + 65);
                let content = bounded_bytes(data, offset + 73, 128);
                let (cmd, attrs) = build_write_command(&path, file_offset, &content);
                add_command(&mut builder, cmd, attrs);
                offset += 202;
            }
            3 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let mode = bounded_u64(data, offset + 65) & 0o7777;
                let (cmd, attrs) = build_chmod_command(&path, mode);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            4 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let uid = bounded_u64(data, offset + 65);
                let gid = bounded_u64(data, offset + 73);
                let (cmd, attrs) = build_chown_command(&path, uid, gid);
                add_command(&mut builder, cmd, attrs);
                offset += 81;
            }
            5 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let size = bounded_u64(data, offset + 65);
                let (cmd, attrs) = build_truncate_command(&path, size);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            6 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/link_");
                let ino = bounded_u64(data, offset + 65);
                let target = bounded_path(data, offset + 73, b"target_");
                let (cmd, attrs) = build_symlink_command(&path, ino, &target);
                add_command(&mut builder, cmd, attrs);
                offset += 138;
            }
            7 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let name = bounded_bytes(data, offset + 65, 32);
                if !name.is_empty() {
                    let value = bounded_bytes(data, offset + 98, 64);
                    let (cmd, attrs) = build_setxattr_command(&path, &name, &value);
                    add_command(&mut builder, cmd, attrs);
                }
                offset += 163;
            }
            8 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let name = bounded_bytes(data, offset + 65, 32);
                if !name.is_empty() {
                    let (cmd, attrs) = build_removexattr_command(&path, &name);
                    add_command(&mut builder, cmd, attrs);
                }
                offset += 98;
            }
            9 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/old_");
                let path_to = bounded_path(data, offset + 65, b"fuzz_subvol/new_");
                let (cmd, attrs) = build_rename_command(&path, &path_to);
                add_command(&mut builder, cmd, attrs);
                offset += 130;
            }
            10 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let link_path = bounded_path(data, offset + 65, b"fuzz_subvol/hardlink_");
                let (cmd, attrs) = build_link_command(&path, &link_path);
                add_command(&mut builder, cmd, attrs);
                offset += 130;
            }
            11 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let (cmd, attrs) = build_unlink_command(&path);
                add_command(&mut builder, cmd, attrs);
                offset += 65;
            }
            12 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/dir_");
                let (cmd, attrs) = build_rmdir_command(&path);
                add_command(&mut builder, cmd, attrs);
                offset += 65;
            }
            13 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/dev_");
                let ino = bounded_u64(data, offset + 65);
                let mode = bounded_u64(data, offset + 73) & 0o7777 | 0o60000;
                let rdev = bounded_u64(data, offset + 81);
                let (cmd, attrs) = build_mknod_command(&path, ino, mode, rdev);
                add_command(&mut builder, cmd, attrs);
                offset += 89;
            }
            14 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/fifo_");
                let ino = bounded_u64(data, offset + 65);
                let (cmd, attrs) = build_mkfifo_command(&path, ino);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            15 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/sock_");
                let ino = bounded_u64(data, offset + 65);
                let (cmd, attrs) = build_mksock_command(&path, ino);
                add_command(&mut builder, cmd, attrs);
                offset += 73;
            }
            16 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let atime_sec = bounded_i64(data, offset + 65);
                let atime_nsec = bounded_i32(data, offset + 73);
                let mtime_sec = bounded_i64(data, offset + 77);
                let mtime_nsec = bounded_i32(data, offset + 85);
                let ctime_sec = bounded_i64(data, offset + 89);
                let ctime_nsec = bounded_i32(data, offset + 97);
                let (cmd, attrs) = build_utimes_command(
                    &path, atime_sec, atime_nsec, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
                );
                add_command(&mut builder, cmd, attrs);
                offset += 101;
            }
            17 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let file_offset = bounded_u64(data, offset + 65);
                let len = bounded_u64(data, offset + 73);
                let (cmd, attrs) = build_update_extent_command(&path, file_offset, len);
                add_command(&mut builder, cmd, attrs);
                offset += 81;
            }
            18 => {
                let path = bounded_path(data, offset, b"fuzz_subvol/file_");
                let file_offset = bounded_u64(data, offset + 65);
                let len = bounded_u64(data, offset + 73);
                let clone_uuid = bounded_uuid(data, offset + 81);
                let clone_ctransid = bounded_u64(data, offset + 97);
                let clone_path = bounded_path(data, offset + 105, b"fuzz_subvol/src_");
                let clone_offset = bounded_u64(data, offset + 170);
                let (cmd, attrs) = build_clone_command(
                    &path,
                    file_offset,
                    len,
                    &clone_uuid,
                    clone_ctransid,
                    &clone_path,
                    clone_offset,
                );
                add_command(&mut builder, cmd, attrs);
                offset += 178;
            }
            _ => {
                let snap_uuid = bounded_uuid(data, offset);
                let snap_ctransid = bounded_u64(data, offset + 16);
                let clone_uuid = bounded_uuid(data, offset + 24);
                let clone_ctransid = bounded_u64(data, offset + 40);
                let (cmd, attrs) = build_snapshot_command(
                    b"fuzz_snapshot",
                    &snap_uuid,
                    snap_ctransid,
                    &clone_uuid,
                    clone_ctransid,
                );
                add_command(&mut builder, cmd, attrs);
                offset += 48;
            }
        }
    }

    builder.finalize();
    let stream = builder.finish();

    // MR-1: Round-trip — builder output must parse successfully
    let parsed = parse_send_stream(&stream);
    assert!(
        parsed.is_ok(),
        "SendStreamBuilder output must always parse: {:?}",
        parsed.err()
    );
    let parsed = parsed.unwrap();

    // MR-2: Version must be 1
    assert_eq!(parsed.version, 1, "stream version must be 1");

    // MR-3: Must have at least subvol + end commands
    assert!(
        parsed.commands.len() >= 2,
        "must have at least subvol and end commands"
    );

    // MR-4: First command must be Subvol (or Snapshot for incremental)
    assert!(
        matches!(
            parsed.commands[0].cmd,
            SendCommand::Subvol | SendCommand::Snapshot
        ),
        "first command must be Subvol or Snapshot"
    );

    // MR-5: Last command must be End
    assert_eq!(
        parsed.commands.last().unwrap().cmd,
        SendCommand::End,
        "last command must be End"
    );

    // MR-6: Determinism — parsing twice yields identical results
    let parsed2 = parse_send_stream(&stream).unwrap();
    assert_eq!(
        parsed.version, parsed2.version,
        "determinism: version must match"
    );
    assert_eq!(
        parsed.commands.len(),
        parsed2.commands.len(),
        "determinism: command count must match"
    );
});
