#![forbid(unsafe_code)]

use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub snapshot: Snapshot,
    writes: BTreeMap<BlockNumber, Vec<u8>>,
}

impl Transaction {
    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.writes.insert(block, bytes);
    }

    #[must_use]
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]> {
        self.writes.get(&block).map(Vec::as_slice)
    }

    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.writes.len()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    #[error(
        "first-committer-wins conflict on block {block}: snapshot={snapshot:?}, observed={observed:?}"
    )]
    Conflict {
        block: BlockNumber,
        snapshot: CommitSeq,
        observed: CommitSeq,
    },
}

#[derive(Debug, Clone, Default)]
pub struct MvccStore {
    next_txn: u64,
    next_commit: u64,
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        let txn = Transaction {
            id: TxnId(self.next_txn),
            snapshot: self.current_snapshot(),
            writes: BTreeMap::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        for block in txn.writes.keys() {
            let latest = self.latest_commit_seq(*block);
            if latest > txn.snapshot.high {
                return Err(CommitError::Conflict {
                    block: *block,
                    snapshot: txn.snapshot.high,
                    observed: latest,
                });
            }
        }

        let commit_seq = CommitSeq(self.next_commit);
        self.next_commit = self.next_commit.saturating_add(1);

        for (block, bytes) in txn.writes {
            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn.id,
                bytes,
            });
        }

        Ok(commit_seq)
    }

    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<&[u8]> {
        self.versions.get(&block).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|v| v.commit_seq <= snapshot.high)
                .map(|v| v.bytes.as_slice())
        })
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        for versions in self.versions.values_mut() {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                versions.drain(0..keep_from);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_and_fcw_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1, 2, 3]);
        t2.stage_write(BlockNumber(7), vec![9, 9, 9]);

        let c1 = store.commit(t1).expect("t1 commit");
        assert_eq!(c1, CommitSeq(1));

        let err = store.commit(t2).expect_err("t2 should conflict");
        match err {
            CommitError::Conflict { block, .. } => assert_eq!(block, BlockNumber(7)),
        }
    }

    #[test]
    fn read_snapshot_visibility() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        let _ = store.commit(t1).expect("commit t1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        let _ = store.commit(t2).expect("commit t2");

        let visible = store
            .read_visible(BlockNumber(1), snap)
            .expect("visible data at snap");
        assert_eq!(visible, &[1]);
    }
}
