//! Mounted namespace exchange. The FsOps caller retains the exclusive operation
//! guard until both native publication and the two inode mappings are complete.

use super::{FatFs, FfsError, InodeNumber, OsStr, Result, checkpoint, map_mutation_error};
use asupersync::Cx;

impl FatFs {
    pub(super) fn exchange_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        let from_dir = self.node(cx, parent)?.directory()?;
        let to_dir = self.node(cx, new_parent)?.directory()?;
        let (from, from_name) = self.child_path(parent, name)?;
        let (to, to_name) = self.child_path(new_parent, new_name)?;
        let source = self.visible_lookup(cx, from_dir, &from_name)?;
        let target = self.visible_lookup(cx, to_dir, &to_name)?;
        // Reserve BOTH mount-lifetime identities before any native write.
        // A capacity refusal must not leave a published exchange without IDs.
        let source_ino = self.register(cx, parent, source.clone())?;
        let target_ino = self.register(cx, new_parent, target.clone())?;
        self.volume.rename_exchange(cx, &from, &to, false)
            .map_err(map_mutation_error)?;
        if source_ino == target_ino {
            return Ok(());
        }
        let at_from = self.volume.lookup(cx, from_dir, &from_name)?;
        let at_to = self.volume.lookup(cx, to_dir, &to_name)?;
        if at_from.offset != source.offset || at_to.offset != target.offset {
            return Err(FfsError::Corruption {
                block: source.offset / 512,
                detail: "exchange moved a native name slot during cache publication".into(),
            });
        }
        let mut state = self.state()?;
        Self::invalidate_cached_chain(&mut state, source_ino);
        Self::invalidate_cached_chain(&mut state, target_ino);
        state.free_clusters = None;
        // Inodes follow objects, NOT names/slots. Cached descendants continue
        // to refer to the same directory inode, whose own parent now changes.
        let source_node = state.nodes.get_mut(&source_ino).ok_or_else(|| {
            FfsError::NotFound(format!("FAT exchange inode {}", source_ino.0))
        })?;
        source_node.parent = new_parent;
        source_node.entry = Some(at_to);
        let target_node = state.nodes.get_mut(&target_ino).ok_or_else(|| {
            FfsError::NotFound(format!("FAT exchange inode {}", target_ino.0))
        })?;
        target_node.parent = parent;
        target_node.entry = Some(at_from);
        state.slot_to_ino.insert(source.offset, target_ino);
        state.slot_to_ino.insert(target.offset, source_ino);
        drop(state);
        checkpoint(cx)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
