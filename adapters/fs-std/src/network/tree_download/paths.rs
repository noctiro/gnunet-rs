//! Bounded path admission from authenticated parent entries.
use super::TreeDownloadOptions;
use crate::{Error, Result};
use gnunet_fs::{
    Uri,
    directory::{self as dir, VerifiedEntry, walk},
};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};
pub(crate) struct Job {
    pub id: [u8; 64],
    pub parent: Option<[u8; 64]>,
    pub kind: walk::Kind,
    pub(crate) path: Arc<PathBuf>,
    pub(crate) target: [u8; 32],
    pub(crate) inline: Option<Vec<u8>>,
}
pub(crate) struct Paths {
    pub(crate) jobs: Vec<Job>,
    pub(crate) names: BTreeSet<Arc<PathBuf>>,
    pub(crate) path_bytes: usize,
    pub(crate) inline_bytes: usize,
}
impl Paths {
    pub(crate) fn admit(
        &mut self,
        owner: &mut walk::Walk<'_>,
        parent: walk::AttemptId<'_>,
        base: &Path,
        verified: VerifiedEntry<'_>,
        options: TreeDownloadOptions,
    ) -> Result<()> {
        let entry = verified.entry();
        let uri = entry.uri()?;
        let kind = if dir::claims_directory(entry.metadata.items()) == Some(true) {
            walk::Kind::Directory
        } else {
            walk::Kind::File
        };
        let fallback;
        let name = match dir::filename(entry.metadata.items()) {
            Some(name) => name,
            None => {
                fallback = format!("entry-{}", entry.range.start);
                fallback.as_bytes()
            }
        };
        // Official scanners commonly append '/' to directory names. Remove
        // exactly that marker; all actual output names remain single components.
        let name = if kind == walk::Kind::Directory {
            name.strip_suffix(b"/").unwrap_or(name)
        } else {
            name
        };
        validate_name(name)?;
        let path = base.join(OsStr::from_bytes(name));
        if path.as_os_str().as_bytes().len() > 4096 {
            return Err(Error::Limit);
        }
        let charged = self
            .path_bytes
            .checked_add(path.as_os_str().as_bytes().len())
            .ok_or(Error::Limit)?;
        if charged > options.max_path_bytes {
            return Err(Error::Limit);
        }
        if self.names.contains(&path) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "directory entries name the same output path",
            )
            .into());
        }
        let content = match uri {
            Uri::Content(c) => Some(c),
            Uri::Location(c) => Some(c.content()),
            _ => None,
        };
        let hint = content.and_then(|content| {
            dir::hints(entry.metadata.items()).find(|hint| {
                hint.item.data.len() as u128 == u128::from(content.size)
                    && hint.item.data.len() <= options.max_inline_bytes
            })
        });
        let mut inline = None;
        let mut inline_charge = self.inline_bytes;
        if let Some(hint) = hint {
            inline_charge = inline_charge
                .checked_add(hint.item.data.len())
                .ok_or(Error::Limit)?;
            if inline_charge > options.max_total_inline_bytes {
                return Err(Error::Limit);
            }
            let mut copy = Vec::new();
            copy.try_reserve_exact(hint.item.data.len())
                .map_err(|_| Error::Limit)?;
            copy.extend_from_slice(hint.item.data);
            inline = Some(copy);
        }
        self.jobs.try_reserve(1).map_err(|_| Error::Limit)?;
        let admission = owner.admit(parent, verified, kind)?;
        let task = match admission {
            walk::Admission::Queued(task) | walk::Admission::Namespace(task) => task,
            _ => return Err(Error::Corrupt),
        };
        if owner.ordinal(task)? != self.jobs.len() {
            return Err(Error::Corrupt);
        }
        let path = Arc::new(path);
        self.names.insert(path.clone());
        let parent_id = self
            .jobs
            .get(owner.ordinal(parent.task())?)
            .ok_or(Error::Corrupt)?
            .id;
        let mut binding = gnunet_crypto::Hash512State::new();
        binding.update(b"GNUnet Rust directory member v1\0");
        binding.update(&parent_id);
        binding.update(&verified.source().key);
        binding.update(&verified.source().query);
        binding.update(&verified.source().size.to_be_bytes());
        binding.update(&entry.range.start.to_be_bytes());
        binding.update(&entry.range.end.to_be_bytes());
        binding.update(&(entry.raw_uri.len() as u64).to_be_bytes());
        binding.update(entry.raw_uri);
        binding.update(&(name.len() as u64).to_be_bytes());
        binding.update(name);
        binding.update(&[if kind == walk::Kind::Directory { 1 } else { 0 }]);
        self.jobs.push(Job {
            id: binding.finish(),
            parent: Some(parent_id),
            kind,
            path,
            target: match uri {
                Uri::Location(loc) => *loc.peer().as_bytes(),
                _ => [0; 32],
            },
            inline,
        });
        self.path_bytes = charged;
        self.inline_bytes = inline_charge;
        Ok(())
    }
}
fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty()
        || name == b"."
        || name == b".."
        || name.iter().any(|b| matches!(b, b'/' | b'\\' | 0))
        || (name.len() >= 2 && name[0].is_ascii_alphabetic() && name[1] == b':')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory entry is not a safe output basename",
        )
        .into());
    }
    Ok(())
}

pub(crate) fn root_id(content: gnunet_fs::Content) -> [u8; 64] {
    let mut hash = gnunet_crypto::Hash512State::new();
    hash.update(b"GNUnet Rust directory root v1\0");
    hash.update(&content.key);
    hash.update(&content.query);
    hash.update(&content.size.to_be_bytes());
    hash.finish()
}
