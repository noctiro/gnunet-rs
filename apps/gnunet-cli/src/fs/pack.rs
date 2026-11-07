//! Explicit regular-file lists packed into a local official GNUnet directory.
use gnunet::{
    fs::{
        Content, directory as dir,
        metadata::{self as md, Compression},
    },
    fs_codec::{Compressor, Inflate},
    fs_host::{Buffers, Control, Limits, Repository},
};
use std::{error::Error, ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_FILES: usize = 4096;
const MAX_NAME_BYTES: usize = 8192;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_TOTAL_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;

fn add_budget(total: &mut usize, amount: usize, limit: usize) -> Result<()> {
    *total = total.checked_add(amount).ok_or(md::Error::Overflow)?;
    if *total > limit {
        return Err(gnunet::fs_host::Error::Limit.into());
    }
    Ok(())
}
fn bytes(length: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length)?;
    buffer.resize(length, 0);
    Ok(buffer)
}
fn basename(path: &Path) -> Result<&[u8]> {
    let name = path
        .file_name()
        .ok_or("FS pack input needs a file name")?
        .as_bytes();
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.contains(&0) {
        return Err("FS pack file name is empty, too long or contains NUL".into());
    }
    Ok(name)
}
fn raw_metadata_bytes(item: md::Item<'_>) -> Result<usize> {
    md::HEADER_BYTES
        .checked_add(md::ENTRY_BYTES)
        .and_then(|n| n.checked_add(item.data.len()))
        .and_then(|n| n.checked_add(item.plugin.map_or(0, <[u8]>::len)))
        .and_then(|n| n.checked_add(item.mime.map_or(0, <[u8]>::len)))
        .ok_or_else(|| md::Error::Overflow.into())
}

struct MetadataBuffers {
    plain: Vec<u8>,
    coded: Vec<u8>,
    compressor: Compressor,
}
impl MetadataBuffers {
    fn new() -> Result<Self> {
        Ok(Self {
            plain: bytes(MAX_METADATA_BYTES)?,
            coded: bytes(MAX_METADATA_BYTES)?,
            compressor: Compressor::new(),
        })
    }
    fn encode(&mut self, item: md::Item<'_>, compression: Compression) -> Result<Vec<u8>> {
        let mut order = [0];
        let plan = md::plan(
            &[item],
            &mut order,
            &mut self.plain,
            &mut self.coded,
            &mut self.compressor,
            md::Limits {
                max_coded_bytes: MAX_METADATA_BYTES,
                max_plain_bytes: MAX_METADATA_BYTES,
                max_entries: 1,
            },
            md::Options {
                compression,
                max_output_bytes: MAX_METADATA_BYTES,
                ..md::Options::default()
            },
        )?;
        let mut output = bytes(plan.report().wire_bytes)?;
        plan.write(&mut output)?;
        Ok(output)
    }
}

struct Entry {
    content: Content,
    metadata: Vec<u8>,
    record: Vec<u8>,
}

/// Import each selected descriptor and stream a directory of those real CHKs.
/// Basenames retain their Unix bytes; duplicate names remain distinct entries.
/// Limits bound retained metadata and record arenas before any file is read.
/// Files already imported remain useful if a later input fails. Size/mtime are
/// checked on the same descriptor around its read; this is not a source snapshot.
pub(super) fn pack(repository: &OsStr, files: &[impl AsRef<OsStr>]) -> Result<Content> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err("FS pack requires between 1 and 4096 explicit files".into());
    }
    let longest_uri = Content {
        key: [0; 64],
        query: [0; 64],
        size: u64::MAX,
    }
    .uri()
    .encoded_len()?;
    let mut metadata_bound = raw_metadata_bytes(dir::MIME_ITEM)?;
    let mut record_bound = 12 + metadata_bound;
    for input in files {
        let name = basename(Path::new(input.as_ref()))?;
        let raw = md::HEADER_BYTES + md::ENTRY_BYTES + name.len() + 1;
        add_budget(&mut metadata_bound, raw, MAX_TOTAL_METADATA_BYTES)?;
        let record = longest_uri
            .checked_add(5)
            .and_then(|n| n.checked_add(raw))
            .ok_or(md::Error::Overflow)?;
        add_budget(&mut record_bound, record, MAX_TOTAL_RECORD_BYTES)?;
    }

    let mut metadata = MetadataBuffers::new()?;
    let root_bytes = metadata.encode(dir::MIME_ITEM, Compression::Never)?;
    let mut owned = Vec::new();
    owned.try_reserve_exact(files.len())?;
    let mut repository = Repository::open(repository)?;
    let mut buffers = Buffers::new();
    let total_limits = Limits::default();
    let mut total_plain = 0;
    let mut total_encoded = 0;
    for path in files {
        let path = Path::new(path.as_ref());
        let mut input = gnunet::fs_host::open_input(path)?;
        let before = input.metadata()?;
        if !before.is_file() {
            return Err("FS pack requires regular files".into());
        }
        let modified = before.modified()?;
        let name = basename(path)?;
        let mut terminated = bytes(name.len() + 1)?;
        terminated[..name.len()].copy_from_slice(name);
        let encoded_metadata = metadata.encode(
            md::Item {
                kind: 180,
                format: md::Format::CString,
                data: &terminated,
                plugin: None,
                mime: None,
            },
            Compression::Adaptive,
        )?;
        let record_size = longest_uri + 5 + encoded_metadata.len();
        let record = bytes(record_size)?;
        let result = buffers.publish(
            &mut input,
            before.len(),
            &mut repository,
            Limits {
                max_file_bytes: total_limits.max_file_bytes - total_plain,
                max_encoded_bytes: total_limits.max_encoded_bytes - total_encoded,
            },
            |_| Control::Continue,
        )?;
        let after = input.metadata()?;
        if after.len() != before.len() || after.modified()? != modified {
            return Err(gnunet::fs_host::Error::SourceChanged.into());
        }
        total_plain += result.progress.plaintext_bytes;
        total_encoded += result.progress.encoded_bytes;
        owned.push(Entry {
            content: result.content,
            metadata: encoded_metadata,
            record,
        });
    }

    // All Vec owners are now fixed. PreparedEntry borrows each distinct record
    // arena until the final directory stream has been completely encoded.
    let root = dir::PreparedMetadata::validate(
        &root_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(owned.len())?;
    let mut inflater = Inflate::new();
    for entry in &mut owned {
        let prepared = dir::PreparedMetadata::validate(
            &entry.metadata,
            &mut metadata.plain,
            &mut inflater,
            md::Limits::default(),
        )?;
        entries.push(dir::PreparedEntry::prepare(
            entry.content.uri(),
            prepared,
            &mut entry.record,
        )?);
    }
    let mut placements = Vec::new();
    placements.try_reserve_exact(entries.len())?;
    placements.resize(entries.len(), dir::Placement::default());
    let plan = dir::plan(
        root,
        &entries,
        &mut placements,
        dir::BuildOptions {
            max_output_bytes: MAX_DIRECTORY_BYTES,
            max_source_entries: MAX_FILES,
            max_entries: MAX_FILES,
            max_trials: MAX_FILES,
            ..dir::BuildOptions::default()
        },
    )?;
    Ok(buffers
        .publish_directory(
            &plan,
            &mut repository,
            Limits {
                max_file_bytes: total_limits.max_file_bytes - total_plain,
                max_encoded_bytes: total_limits.max_encoded_bytes - total_encoded,
            },
            |_| Control::Continue,
        )?
        .content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs::{self, DirBuilder},
        os::unix::{ffi::OsStringExt, fs::DirBuilderExt},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            match fs::remove_dir_all(&self.0) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "One real disk test asserts raw filename and authenticated child content"
    )]
    fn packs_native_filename_bytes_and_empty_files() -> Result<()> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("gnunet-pack-{}-{nonce}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path)?;
        let temporary = Temporary(path);
        // APFS rejects invalid UTF-8 at file creation. Keep exact native bytes
        // on that platform too; Linux exercises opaque non-UTF8 filenames.
        let name = if cfg!(target_os = "macos") {
            b"name-\xc3\xa9".to_vec()
        } else {
            vec![0xff, b'a', 0xfe]
        };
        let input = temporary.0.join(OsString::from_vec(name.clone()));
        let empty = temporary.0.join("empty");
        let data: Vec<_> = (0..70_000).map(|n| (n % 251) as u8).collect();
        fs::write(&input, &data)?;
        fs::write(&empty, b"")?;
        let root = temporary.0.join("repository");
        let files = [input.into_os_string(), empty.into_os_string()];
        let content = pack(root.as_os_str(), &files)?;
        let mut repository = Repository::open(&root)?;
        let mut buffers = Buffers::new();
        let mut children = Vec::new();
        let receipt = buffers.visit_directory(
            &mut repository,
            content,
            Limits::default(),
            dir::Limits::default(),
            |proof| {
                assert_eq!(proof.source(), content);
                let entry = proof.entry();
                let item = entry
                    .metadata
                    .items()
                    .find(|item| item.kind == 180)
                    .ok_or(gnunet::fs_host::Error::Corrupt)?;
                assert_eq!(item.format, md::Format::CString);
                assert_eq!(item.data.last(), Some(&0));
                let gnunet::fs::Uri::Content(child) = entry.uri()? else {
                    return Err(gnunet::fs_host::Error::Corrupt);
                };
                children.push((item.data[..item.data.len() - 1].to_vec(), child));
                Ok(())
            },
        )?;
        assert_eq!(receipt.entries(), 2);
        assert_eq!(children[0].0, name);
        assert_eq!(children[1].0, b"empty");
        for (index, (_, child)) in children.iter().enumerate() {
            let mut output = Vec::new();
            let receipt = buffers.copy_to(
                &mut repository,
                *child,
                &mut output,
                Limits::default(),
                |_| Control::Continue,
            )?;
            assert_eq!(receipt.verified.content(), *child);
            assert_eq!(
                output.as_slice(),
                if index == 0 { data.as_slice() } else { b"" }
            );
        }
        let too_many = vec![OsString::from("unused"); MAX_FILES + 1];
        let refused = temporary.0.join("never-created");
        assert!(pack(refused.as_os_str(), &too_many).is_err());
        assert!(!refused.exists());
        Ok(())
    }
}
