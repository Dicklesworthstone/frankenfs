//! Owned WAL admission with durable recovered bytes and namespace publication.
//!
//! Every opener syncs the owned file before recovery can publish its records:
//! a previous process may have left complete but unsynced records in page cache.
//! Resetting a writer's pending counter does not make those records durable.
//! A file fsync also does not make its containing directory entry durable. Every
//! opener establishes both barriers, including retries and existing names.
//! The caller must keep the directory tree and intermediate symlinks stable and
//! durable. Advisory inode ownership does not exclude external path replacement.

use ffs_error::{FfsError, Result};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Acquire ownership and establish durability before recovery or publication.
/// Neither a competing opener nor a failed barrier changes WAL bytes.
/// The returned descriptor retains ownership until its last clone is closed.
pub fn open_owned_wal(path: &Path) -> Result<File> {
    open_with_barriers(path, File::sync_all, File::sync_all)
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

// Retain the directory-fault tests on the production protocol, including the
// actual file barrier. Production does not expose either fault-injection seam.
#[cfg(test)]
fn open_with_directory_sync(
    path: &Path,
    sync_directory: impl FnMut(&File) -> io::Result<()>,
) -> Result<File> {
    open_with_barriers(path, File::sync_all, sync_directory)
}

// Keep the real open/lock/path-resolution protocol shared with fault tests.
// Only the durability syscalls are injectable; production passes sync_all for both.
fn open_with_barriers(
    path: &Path,
    sync_file: impl FnOnce(&File) -> io::Result<()>,
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
    // Complete CRC-valid records may still be dirty in the kernel after a
    // Manual/EveryN writer exits. Recovery initializes pending_sync_count to
    // zero, so a subsequent flush would not sync those records. Stabilize the
    // entire existing inode BEFORE replay, tail repair or exposing a writer.
    // Even an empty file receives the barrier; header initialization and tail
    // trimming retain their separate barriers after they change the file.
    sync_file(&file)?;
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
    use crate::persist::PersistentMvccStore;
    use crate::wal::{self, HEADER_SIZE, WalCommit, WalHeader, WalWrite};
    use crate::wal_replay::{TailPolicy, WalReplayEngine};
    use crate::wal_writer::{SyncPolicy, WalWriter, WalWriterConfig};
    use asupersync::Cx;
    use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
    use std::cell::Cell;
    use std::io::Write;
    use std::os::unix::fs::{FileExt, symlink};

    fn assert_owned(path: &Path) {
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
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
            assert!(
                error
                    .to_string()
                    .contains("injected directory sync failure")
            );
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
        assert_eq!(
            barriers,
            vec![identity(&Path::new(".").metadata().unwrap())]
        );
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

    fn record(seq: u64, byte: u8) -> WalCommit {
        WalCommit {
            commit_seq: CommitSeq(seq),
            txn_id: TxnId(seq),
            writes: vec![WalWrite {
                block: BlockNumber(7),
                data: vec![byte; 128],
            }],
        }
    }

    #[test]
    fn admission_syncs_new_and_existing_inode_before_publishing_either_name() {
        let mut committed = wal::encode_header(&WalHeader::default()).to_vec();
        committed.extend_from_slice(&wal::encode_commit(&record(1, 11)).unwrap());
        for initial in [None, Some(Vec::new()), Some(committed)] {
            let directory = tempfile::tempdir().unwrap();
            let alias_dir = directory.path().join("aliases");
            std::fs::create_dir(&alias_dir).unwrap();
            let target = directory.path().join("state.wal");
            let alias = alias_dir.join("state.wal");
            if let Some(bytes) = &initial {
                std::fs::write(&target, bytes).unwrap();
            }
            symlink(&target, &alias).unwrap();
            let phase = Cell::new(0);
            let file = open_with_barriers(
                &alias,
                |owned| {
                    assert_eq!(phase.get(), 0);
                    assert_owned(&target);
                    assert_owned(&alias);
                    assert_eq!(identity(&owned.metadata()?), identity(&target.metadata()?));
                    owned.sync_all()?;
                    phase.set(1);
                    Ok(())
                },
                |parent| {
                    assert!(matches!(phase.get(), 1 | 2), "file barrier must be first");
                    parent.sync_all()?;
                    phase.set(phase.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(phase.get(), 3);
            assert_eq!(std::fs::read(&target).unwrap(), initial.unwrap_or_default());
            assert_owned(&target);
            drop(file);
        }
    }

    #[test]
    fn deferred_prefix_is_synced_before_recovered_writer_has_zero_pending() {
        for policy in [SyncPolicy::Manual, SyncPolicy::EveryN(3)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.wal");
            let config = WalWriterConfig {
                sync_policy: policy,
                ..WalWriterConfig::default()
            };
            let mut writer = WalWriter::create(&path, config.clone()).unwrap();
            let records = [record(1, 11), record(2, 22)];
            for record in &records {
                assert!(!writer.append_commit(record).unwrap().synced);
            }
            assert_eq!(writer.pending_sync_count(), 2);
            let position = writer.size();
            let prefix = std::fs::read(&path).unwrap();
            // Drop does not flush. A process restart is not a power cut: the
            // complete records can remain readable in the kernel's dirty cache.
            drop(writer);

            let synced = Cell::new(false);
            let file = open_with_barriers(
                &path,
                |owned| {
                    assert_owned(&path);
                    let mut observed = vec![0; prefix.len()];
                    owned.read_exact_at(&mut observed, 0)?;
                    assert_eq!(observed, prefix);
                    owned.sync_all()?;
                    synced.set(true);
                    Ok(())
                },
                |parent| {
                    assert!(synced.get(), "do not expose a namespace before its data");
                    parent.sync_all()
                },
            )
            .unwrap();
            assert!(synced.get());
            let mut bytes = vec![0; prefix.len()];
            file.read_exact_at(&mut bytes, 0).unwrap();
            let mut replayed = Vec::new();
            let report = WalReplayEngine::new(TailPolicy::FailFast)
                .replay(&bytes[HEADER_SIZE..], 0, |record| {
                    replayed.push(record.clone())
                })
                .unwrap();
            assert!(report.outcome.is_clean());
            assert_eq!(replayed, records);

            let mut recovered = WalWriter::new(file, position, config);
            recovered.set_last_commit_seq(2);
            assert_eq!(recovered.pending_sync_count(), 0);
            assert_eq!(recovered.flush().unwrap(), 0);
            // Only the recovered prefix was synced. New appends still obey the
            // configured policy rather than inheriting the old pending count.
            assert!(!recovered.append_commit(&record(3, 33)).unwrap().synced);
            assert_eq!(recovered.flush().unwrap(), 1);
            drop(recovered);

            let store = PersistentMvccStore::open(&Cx::for_testing(), &path).unwrap();
            assert_eq!(store.wal_stats().replayed_commits, 3);
            assert_eq!(store.current_snapshot().high, CommitSeq(3));
            for (seq, byte) in [(1, 11), (2, 22), (3, 33)] {
                assert_eq!(
                    store.read_visible(
                        BlockNumber(7),
                        Snapshot {
                            high: CommitSeq(seq)
                        }
                    ),
                    Some(vec![byte; 128])
                );
            }
        }
    }

    #[test]
    fn failed_prefix_sync_preserves_tail_until_successful_recovery_admission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.wal");
        let mut writer = WalWriter::create(
            &path,
            WalWriterConfig {
                sync_policy: SyncPolicy::Manual,
                ..WalWriterConfig::default()
            },
        )
        .unwrap();
        assert!(!writer.append_commit(&record(1, 11)).unwrap().synced);
        let valid_bytes = writer.size();
        drop(writer);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x12, 0x34, 0x56])
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let error = open_with_barriers(
            &path,
            |_| {
                assert_owned(&path);
                Err(io::Error::other("injected recovered-prefix sync failure"))
            },
            |_| panic!("failed file sync must prevent namespace publication"),
        )
        .unwrap_err();
        assert!(matches!(&error, FfsError::Io(_)));
        assert!(error.to_string().contains("recovered-prefix sync failure"));
        assert_eq!(std::fs::read(&path).unwrap(), before);

        // Ownership is released, and only a fresh, successful admission allows
        // the real recovery engine to trim the incomplete suffix and publish.
        let cx = Cx::for_testing();
        let store = PersistentMvccStore::open(&cx, &path).unwrap();
        assert_eq!(store.recovery_report().records_discarded, 1);
        assert_eq!(store.recovery_report().wal_valid_bytes, valid_bytes);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_bytes);
        assert_eq!(
            store.read_visible(BlockNumber(7), store.current_snapshot()),
            Some(vec![11; 128])
        );
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(8), vec![8; 16]);
        assert_eq!(store.commit(txn).unwrap(), CommitSeq(2));
        drop(store);
        let reopened = PersistentMvccStore::open(&cx, &path).unwrap();
        assert_eq!(reopened.current_snapshot().high, CommitSeq(2));
        assert_eq!(
            reopened.read_visible(BlockNumber(8), reopened.current_snapshot()),
            Some(vec![8; 16])
        );
    }

    #[test]
    fn competing_owner_and_its_clones_prevent_both_durability_barriers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.wal");
        let owner = open_owned_wal(&path).unwrap();
        let retained = owner.try_clone().unwrap();
        drop(owner);
        let error = open_with_barriers(
            &path,
            |_| panic!("a competing opener must not sync the owner's writes"),
            |_| panic!("a competing opener must not publish the owner's name"),
        )
        .unwrap_err();
        assert!(matches!(error, FfsError::Io(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(retained);
        open_owned_wal(&path).unwrap();
    }
}
