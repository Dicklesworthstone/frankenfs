//! Bounded image-path traversal inside one immutable ZPL head or snapshot.
//!
//! Path splicing follows POSIX pathname resolution, not lexical normalization:
//! a non-directory followed by `.` or `..` still fails. Absolute link targets
//! restart at THIS dataset root; parent traversal above it is refused. No host
//! paths, synthetic .zfs mounts, child datasets or live-head fallbacks are used.

use super::{
    Cx, DirectoryEntry, FfsError, Kind, MAX_COMPONENTS, MAX_PATH, Result, Zpl, checkpoint, corrupt,
    unsupported,
};
use std::collections::VecDeque;

const MAX_SYMLINKS: usize = 40;
const MAX_DIRECTORY_WORK: usize = 64 * 1024 * 1024;

/// Final-link inspection is different from refusing all symlink traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPolicy {
    /// Return a final link itself, but refuse traversing any symbolic link.
    NoSymlinks,
    /// Follow every link, including the final component.
    Follow,
    /// Follow ancestor links; return a final link unless a slash requires a directory.
    NoFollowFinal,
}

#[derive(Debug)]
enum Step {
    Name(Vec<u8>),
    Directory,
}

struct Walk {
    pending: VecDeque<Step>,
    bytes: usize,
    components: usize,
    symlinks: usize,
    directory_work: usize,
}

impl Walk {
    fn new(path: &[u8]) -> Result<Self> {
        let mut walk = Self {
            pending: VecDeque::new(),
            bytes: 0,
            components: 0,
            symlinks: 0,
            directory_work: 0,
        };
        walk.prepend(path)?;
        Ok(walk)
    }

    /// Charge all generated text/components, even those already consumed.
    /// A tiny pending queue or warm metadata cache cannot reset the budget.
    fn prepend(&mut self, path: &[u8]) -> Result<()> {
        if path.contains(&0) {
            return Err(corrupt("ZPL path contains NUL"));
        }
        self.bytes = self
            .bytes
            .checked_add(path.len())
            .filter(|&bytes| bytes <= MAX_PATH)
            .ok_or(FfsError::NameTooLong)?;
        let count = path
            .split(|&byte| byte == b'/')
            .filter(|part| !part.is_empty())
            .count();
        self.components = self
            .components
            .checked_add(count)
            .filter(|&components| components <= MAX_COMPONENTS)
            .ok_or(FfsError::NameTooLong)?;
        // Keep the directory requirement at the END OF THIS EXPANSION, before
        // the saved suffix. Dropping a target's trailing slash changes semantics.
        if path.last() == Some(&b'/') {
            self.pending.push_front(Step::Directory);
        }
        for component in path
            .rsplit(|&byte| byte == b'/')
            .filter(|part| !part.is_empty())
        {
            if component.len() > 255 {
                return Err(FfsError::NameTooLong);
            }
            self.pending.push_front(Step::Name(component.to_vec()));
        }
        Ok(())
    }

    fn follow(&mut self) -> Result<()> {
        if self.symlinks == MAX_SYMLINKS {
            return Err(loop_error());
        }
        self.symlinks += 1;
        Ok(())
    }

    fn directory(&mut self, cx: &Cx, entries: &[DirectoryEntry]) -> Result<()> {
        for entry in entries {
            checkpoint(cx)?;
            let bytes = std::mem::size_of::<DirectoryEntry>()
                + entry.name.len()
                + entry.metadata.inline_symlink.as_ref().map_or(0, Vec::len);
            self.directory_work = self
                .directory_work
                .checked_add(bytes)
                .filter(|&work| work <= MAX_DIRECTORY_WORK)
                .ok_or_else(|| unsupported("ZPL path exceeds 64 MiB directory-work budget"))?;
        }
        Ok(())
    }
}

fn loop_error() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::ELOOP))
}

impl Zpl {
    /// Resolve native bytes without following symlinks. A final link remains
    /// inspectable; use an explicit PathPolicy for normal following semantics.
    pub fn resolve(&mut self, cx: &Cx, path: &[u8]) -> Result<u64> {
        self.resolve_with(cx, path, PathPolicy::NoSymlinks)
    }

    /// All traversal uses the selected view's validated directory and readlink
    /// methods, including native SA/spill/long-link decoding and cancellation.
    /// `..` follows the encountered directory stack, never a file/link's stored
    /// parent: the same symlink inode may have hard links in different directories.
    pub fn resolve_with(&mut self, cx: &Cx, path: &[u8], policy: PathPolicy) -> Result<u64> {
        checkpoint(cx)?;
        let mut walk = Walk::new(path)?;
        let mut directories = vec![self.root];
        let mut current = self.root;
        let mut kind = Kind::Directory;
        while let Some(step) = walk.pending.pop_front() {
            checkpoint(cx)?;
            if kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            let Step::Name(name) = step else {
                continue;
            };
            if name == b"." {
                continue;
            }
            if name == b".." {
                if directories.len() == 1 {
                    return Err(unsupported(
                        "ZPL path would escape the selected dataset root",
                    ));
                }
                directories.pop();
                current = *directories
                    .last()
                    .ok_or_else(|| corrupt("missing ZPL path root"))?;
                continue;
            }
            self.component(&name)?;
            let entries = self.list(cx, current)?;
            walk.directory(cx, &entries)?;
            checkpoint(cx)?;
            let entry = entries
                .into_iter()
                .find(|entry| entry.name == name)
                .ok_or_else(|| FfsError::NotFound("ZPL path component".into()))?;
            let traversal_required = !walk.pending.is_empty() || policy == PathPolicy::Follow;
            if entry.metadata.kind == Kind::Symlink && traversal_required {
                if policy == PathPolicy::NoSymlinks {
                    return Err(loop_error());
                }
                walk.follow()?;
                let target = self.readlink(cx, entry.object)?;
                if target.is_empty() {
                    return Err(FfsError::NotFound("empty ZPL symlink target".into()));
                }
                walk.prepend(&target)?;
                if target.first() == Some(&b'/') {
                    directories.truncate(1);
                    current = self.root;
                }
                // Relative expansion keeps the containing directory, not the
                // symlink's object or its z_parent. No pathname is opened here.
                continue;
            }
            current = entry.object;
            kind = entry.metadata.kind;
            if kind == Kind::Directory {
                if directories.contains(&current) {
                    return Err(corrupt("ZPL path enters an aliased ancestor directory"));
                }
                directories.push(current);
            }
        }
        checkpoint(cx)?;
        Ok(current)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
