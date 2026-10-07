//! Owned WAL admission and durable namespace publication.
//!
//! A file fsync does not make its containing directory entry durable. Every
//! opener establishes that barrier before returning the descriptor, including
//! retries after a failed create and existing names left by another process.
//! The caller must keep the directory tree and intermediate symlinks stable and
//! durable. Advisory inode ownership does not exclude external path replacement.

use ffs_error::{FfsError, Result};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Acquire exclusive inode ownership before recovery, truncation or publication.
/// Neither a competing opener nor a failed directory barrier changes WAL bytes.
/// The returned descriptor retains ownership until its last clone is closed.
pub(crate) fn open_owned_wal(path: &Path) -> Result<File> {
    open_with_directory_sync(path, File::sync_all)
}

fn parent_path(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn verify_name(path: &Path, owned: &Metadata) -> Result<()> {
    if identity(&path.metadata()?) != identity(owned) {
        return Err(FfsError::Io(io::Error::other(
            "WAL pathname changed during ownership admission",
        )));
    }
    Ok(())
}

// Keep the real open/lock/path-resolution protocol shared with fault tests.
// Only the durability syscall is injectable; production always uses sync_all.
fn open_with_directory_sync(
    path: &Path,
    mut sync_directory: impl FnMut(&File) -> io::Result<()>,
) -> Result<File> {
    // Never O_TRUNC: discovering another owner must not erase its log.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let owned = file.metadata()?;
    if !owned.is_file() {
        return Err(FfsError::Format("WAL must be a regular file".to_owned()));
    }
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("WAL is already owned by another writer: {}", path.display()),
        ),
        std::fs::TryLockError::Error(error) => error,
    })?;

    // Resolve AFTER ownership. For a final-component symlink in another
    // directory, syncing only the alias directory would miss a newly created
    // target. Conversely, syncing only the target would miss the alias name.
    let resolved = path.canonicalize()?;
    verify_name(&resolved, &owned)?;
    let target_directory = File::open(parent_path(&resolved))?;
    let requested_directory = File::open(parent_path(path))?;
    let target_meta = target_directory.metadata()?;
    let requested_meta = requested_directory.metadata()?;
    if !target_meta.is_dir() || !requested_meta.is_dir() {
        return Err(FfsError::Format("WAL parent is not a directory".to_owned()));
    }
    sync_directory(&target_directory)?;
    if identity(&target_meta) != identity(&requested_meta) {
        sync_directory(&requested_directory)?;
    }
    // This detects observed replacement, not an exclusion protocol for hostile
    // renames. The caller's stable-namespace obligation remains necessary.
    verify_name(&resolved, &owned)?;
    verify_name(path, &owned)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn assert_owned(path: &Path) {
        let contender = OpenOptions::new().read(true).write(true).open(path).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
    }

    #[test]
    fn admission_syncs_the_directory_on_creation_and_every_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.wal");
        let expected_directory = identity(&directory.path().metadata().unwrap());
        for round in 0..2 {
            let mut barriers = Vec::new();
            let file = open_with_directory_sync(&path, |parent| {
                assert_owned(&path);
                barriers.push(identity(&parent.metadata()?));
                parent.sync_all()
            })
            .unwrap();
            assert_eq!(barriers, vec![expected_directory]);
            if round == 0 {
                use std::os::unix::fs::FileExt;
                file.write_all_at(b"preserve the existing log", 0).unwrap();
                file.sync_all().unwrap();
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), b"preserve the existing log");
            }
            assert_owned(&path);
            drop(file);
        }
    }

    #[test]
    fn competing_owner_is_rejected_before_any_directory_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.wal");
        std::fs::write(&path, b"accepted prefix").unwrap();
        let owner = open_owned_wal(&path).unwrap();
        let error = open_with_directory_sync(&path, |_| {
            panic!("a competing opener must not publish another owner's namespace")
        })
        .unwrap_err();
        assert!(matches!(error, FfsError::Io(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(std::fs::read(&path).unwrap(), b"accepted prefix");
        drop(owner);
        open_owned_wal(&path).unwrap();
    }

    #[test]
    fn directory_sync_failure_preserves_bytes_releases_ownership_and_requires_retry() {
        for existing in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.wal");
            let bytes: &[u8] = if existing { b"accepted prefix" } else { b"" };
            if existing {
                std::fs::write(&path, bytes).unwrap();
            }
            let mut failed_barriers = 0;
            let error = open_with_directory_sync(&path, |_| {
                assert_owned(&path);
                failed_barriers += 1;
                Err(io::Error::other("injected directory sync failure"))
            })
            .unwrap_err();
            assert!(matches!(&error, FfsError::Io(_)));
            assert!(error.to_string().contains("injected directory sync failure"));
            assert_eq!(failed_barriers, 1);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);

            let mut retry_barriers = 0;
            let recovered = open_with_directory_sync(&path, |parent| {
                assert_owned(&path);
                retry_barriers += 1;
                parent.sync_all()
            })
            .unwrap();
            assert_eq!(
                retry_barriers, 1,
                "an existing name does not waive the failed barrier"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            drop(recovered);
        }
    }

    #[test]
    fn cross_directory_symlink_syncs_target_then_alias_and_retains_inode_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let target_dir = directory.path().join("target");
        let alias_dir = directory.path().join("alias");
        std::fs::create_dir(&target_dir).unwrap();
        std::fs::create_dir(&alias_dir).unwrap();
        let target = target_dir.join("state.wal");
        let alias = alias_dir.join("state.wal");
        // Opening through this dangling symlink creates the target, not the link.
        symlink(&target, &alias).unwrap();
        let mut barriers = Vec::new();
        let file = open_with_directory_sync(&alias, |parent| {
            assert_owned(&target);
            assert_owned(&alias);
            barriers.push(identity(&parent.metadata()?));
            parent.sync_all()
        })
        .unwrap();
        assert_eq!(
            barriers,
            vec![
                identity(&target_dir.metadata().unwrap()),
                identity(&alias_dir.metadata().unwrap()),
            ]
        );
        assert!(alias.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            identity(&file.metadata().unwrap()),
            identity(&target.metadata().unwrap())
        );
    }

    #[test]
    fn failure_of_alias_directory_sync_does_not_acknowledge_target_publication() {
        let directory = tempfile::tempdir().unwrap();
        let alias_dir = directory.path().join("aliases");
        std::fs::create_dir(&alias_dir).unwrap();
        let target = directory.path().join("state.wal");
        let alias = alias_dir.join("alias.wal");
        std::fs::write(&target, b"accepted prefix").unwrap();
        symlink(&target, &alias).unwrap();
        let mut barriers = 0;
        let error = open_with_directory_sync(&alias, |parent| {
            barriers += 1;
            assert_owned(&target);
            if barriers == 2 {
                Err(io::Error::other("alias publication failed"))
            } else {
                parent.sync_all()
            }
        })
        .unwrap_err();
        assert_eq!(barriers, 2);
        assert!(error.to_string().contains("alias publication failed"));
        assert_eq!(std::fs::read(&target).unwrap(), b"accepted prefix");
        open_owned_wal(&alias).unwrap();
    }

    #[test]
    fn same_directory_symlink_and_hard_link_do_not_duplicate_barriers() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("state.wal");
        std::fs::write(&target, b"accepted prefix").unwrap();
        let symbolic = directory.path().join("symbolic.wal");
        let hard = directory.path().join("hard.wal");
        symlink(&target, &symbolic).unwrap();
        std::fs::hard_link(&target, &hard).unwrap();
        for path in [&symbolic, &hard] {
            let mut barriers = 0;
            let file = open_with_directory_sync(path, |parent| {
                barriers += 1;
                assert_owned(&target);
                parent.sync_all()
            })
            .unwrap();
            assert_eq!(barriers, 1);
            assert_eq!(
                identity(&file.metadata().unwrap()),
                identity(&target.metadata().unwrap())
            );
            assert_eq!(std::fs::read(path).unwrap(), b"accepted prefix");
        }
    }

    #[test]
    fn bare_filename_uses_current_directory_without_changing_process_cwd() {
        let temporary = tempfile::NamedTempFile::new_in(".").unwrap();
        let path = Path::new(temporary.path().file_name().unwrap());
        let mut barriers = Vec::new();
        let file = open_with_directory_sync(path, |parent| {
            barriers.push(identity(&parent.metadata()?));
            parent.sync_all()
        })
        .unwrap();
        assert_eq!(barriers, vec![identity(&Path::new(".").metadata().unwrap())]);
        assert_eq!(
            identity(&file.metadata().unwrap()),
            identity(&temporary.as_file().metadata().unwrap())
        );
    }

    #[test]
    fn observed_path_replacement_fails_without_truncating_either_inode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.wal");
        let retained = directory.path().join("retained.wal");
        std::fs::write(&path, b"original log").unwrap();
        let error = open_with_directory_sync(&path, |parent| {
            std::fs::rename(&path, &retained)?;
            std::fs::write(&path, b"replacement log")?;
            parent.sync_all()
        })
        .unwrap_err();
        assert!(error.to_string().contains("WAL pathname changed"));
        assert_eq!(std::fs::read(&retained).unwrap(), b"original log");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement log");
        open_owned_wal(&retained).unwrap();
    }
}
