//! Local disk operations over real official blocks and authenticated directories.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible disk tests assert authenticated results and refusal boundaries"
)]
use gnunet_fs::{
    Uri,
    content::{BLOCK_BYTES, NodeRef, TAG_BYTES},
    directory as dir,
    metadata::{self as md, Compression, Format, Item},
};
use gnunet_fs_codec::{Compressor, Inflate};
use gnunet_fs_host::{BlockSource, Buffers, Control, Error, Limits, Repository};
use std::{
    fs::{self, DirBuilder, File},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let instant = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-host-{}-{instant}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}

fn object_path(root: &Path, query: &[u8; 64]) -> PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(128);
    for byte in query {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 15)]));
    }
    root.join(&name[..2]).join(&name[2..])
}

fn binary(kind: u32, data: &[u8]) -> Item<'_> {
    Item {
        kind,
        format: Format::Binary,
        data,
        plugin: None,
        mime: None,
    }
}

fn metadata(items: &[Item<'_>], compression: Compression) -> Result<Vec<u8>, md::Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 256 * 1024];
    let mut coded = vec![0; 256 * 1024];
    let plan = md::plan(
        items,
        &mut order,
        &mut plain,
        &mut coded,
        &mut Compressor::new(),
        md::Limits::default(),
        md::Options {
            compression,
            ..md::Options::default()
        },
    )?;
    assert_eq!(plan.report().compressed, compression == Compression::Always);
    let mut bytes = vec![0; plan.report().wire_bytes];
    plan.write(&mut bytes)?;
    Ok(bytes)
}

struct CountedSource<'a> {
    repository: &'a mut Repository,
    reads: usize,
}
impl BlockSource for CountedSource<'_> {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> gnunet_fs_host::Result<usize> {
        self.reads += 1;
        self.repository.read_block(request, output)
    }
}

#[test]
fn disk_import_reopen_copy_duplicate_and_empty_file() -> TestResult {
    let temporary = Directory::new()?;
    let root = temporary.path("repository");
    let input_path = temporary.path("input");
    let bytes: Vec<_> = (0..2 * BLOCK_BYTES + 723)
        .map(|n| (n % 251) as u8)
        .collect();
    fs::write(&input_path, &bytes)?;
    let mut repository = Repository::open(&root)?;
    let mut buffers = Buffers::new();
    let published = buffers.publish(
        &mut File::open(&input_path)?,
        bytes.len() as u64,
        &mut repository,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(published.content.size, bytes.len() as u64);
    assert_eq!(published.progress.plaintext_bytes, bytes.len() as u64);
    assert!(published.progress.blocks > 1);
    assert_eq!(published.created_blocks, published.progress.blocks);
    let object = object_path(&root, &published.content.query);
    let stored = fs::read(&object)?;
    let inode = fs::metadata(&object)?.ino();
    drop(repository);

    let mut repository = Repository::open(&root)?;
    let duplicate = buffers.publish(
        &mut File::open(&input_path)?,
        bytes.len() as u64,
        &mut repository,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(duplicate.content, published.content);
    assert_eq!(duplicate.created_blocks, 0);
    assert_eq!(fs::metadata(&object)?.ino(), inode);
    assert_eq!(fs::read(&object)?, stored);
    let output_path = temporary.path("copied");
    let read = buffers.copy_to(
        &mut repository,
        published.content,
        &mut File::create(&output_path)?,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(read.verified.content(), published.content);
    assert_eq!(read.progress, published.progress);
    assert_eq!(fs::read(&output_path)?, bytes);

    let empty_path = temporary.path("empty");
    fs::write(&empty_path, [])?;
    let empty = buffers.publish(
        &mut File::open(&empty_path)?,
        0,
        &mut repository,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(empty.progress.plaintext_bytes, 0);
    assert_eq!(empty.progress.blocks, 1);
    assert_eq!(empty.progress.encoded_bytes, TAG_BYTES as u128);
    assert_eq!(
        fs::read(object_path(&root, &empty.content.query))?.len(),
        TAG_BYTES
    );
    let mut output = Vec::new();
    let empty_read = buffers.copy_to(
        &mut repository,
        empty.content,
        &mut output,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(empty_read.verified.content(), empty.content);
    assert!(output.is_empty());
    assert!(!repository.cleanup_pending());
    Ok(())
}

#[test]
fn directory_plan_streams_large_raw_and_compressed_metadata_with_real_parent() -> TestResult {
    let temporary = Directory::new()?;
    let mut repository = Repository::open(temporary.path("repository"))?;
    let mut buffers = Buffers::new();
    let child_bytes = b"actual child content, independent of directory metadata";
    let child = buffers
        .publish(
            &mut child_bytes.as_slice(),
            child_bytes.len() as u64,
            &mut repository,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let root_payload = vec![0xd7; 50_000];
    let raw_payload: Vec<_> = (0..70_000).map(|n| (n % 251) as u8).collect();
    let compressed_payload = vec![0xb3; 80_000];
    let root_bytes = metadata(
        &[dir::MIME_ITEM, binary(900, &root_payload)],
        Compression::Never,
    )?;
    let raw_bytes = metadata(&[binary(901, &raw_payload)], Compression::Never)?;
    let compressed_bytes = metadata(&[binary(902, &compressed_payload)], Compression::Always)?;
    let root = dir::PreparedMetadata::validate(
        &root_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let raw = dir::PreparedMetadata::validate(
        &raw_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let mut decode_scratch = vec![0; 100_000];
    let compressed = dir::PreparedMetadata::validate(
        &compressed_bytes,
        &mut decode_scratch,
        &mut Inflate::new(),
        md::Limits::default(),
    )?;
    let mut raw_arena = vec![0; raw.bytes().len() + 512];
    let mut compressed_arena = vec![0; compressed.bytes().len() + 512];
    let entries = [
        dir::PreparedEntry::prepare(child.uri(), raw, &mut raw_arena)?,
        dir::PreparedEntry::prepare(child.uri(), compressed, &mut compressed_arena)?,
    ];
    let mut placements = [dir::Placement::default(); 2];
    let plan = dir::plan(
        root,
        &entries,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    assert!(plan.report().padding_bytes > 0);
    let mut expected = vec![0; plan.report().wire_bytes as usize];
    plan.write(&mut expected)?;
    let offset = plan.placements()[0].offset - 7;
    let mut crossing = [0xa7; 997];
    let count = plan.read_at(offset, &mut crossing)?;
    assert_eq!(
        &crossing[..count],
        &expected[offset as usize..offset as usize + count]
    );
    assert_eq!(plan.read_at(plan.report().wire_bytes, &mut crossing)?, 0);

    let published = buffers.publish_directory(&plan, &mut repository, Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(published.content.size, plan.report().wire_bytes);
    let mut copied = Vec::new();
    let read = buffers.copy_to(
        &mut repository,
        published.content,
        &mut copied,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(read.verified.content(), published.content);
    assert_eq!(copied, expected);
    let mut seen = Vec::new();
    // A fresh reader has a 4KiB record arena and zero decompression capacity.
    // These actual records force both growth paths without an oversized caller buffer.
    let mut reader = Buffers::new();
    let receipt = reader.visit_directory(
        &mut repository,
        published.content,
        Limits::default(),
        dir::Limits {
            max_record_bytes: 100_000,
            ..dir::Limits::default()
        },
        |proof| {
            assert_eq!(proof.source(), published.content);
            let entry = proof.entry();
            assert!(entry.boundary_tracked);
            assert!(matches!(entry.uri()?, Uri::Content(content) if content == child));
            assert!(entry.metadata.is_complete());
            let item = entry.metadata.items().next().ok_or(Error::Corrupt)?;
            match item.kind {
                901 => {
                    assert_eq!(item.data, raw_payload);
                    assert!(!entry.metadata.was_compressed());
                }
                902 => {
                    assert_eq!(item.data, compressed_payload);
                    assert!(entry.metadata.was_compressed());
                }
                _ => return Err(Error::Corrupt),
            }
            seen.push(item.kind);
            Ok(())
        },
    )?;
    assert_eq!(seen, [901, 902]);
    assert_eq!(receipt.content(), published.content);
    assert_eq!(receipt.entries(), 2);
    Ok(())
}

#[test]
fn corruption_cancel_limits_and_symlinks_never_return_completion() -> TestResult {
    let temporary = Directory::new()?;
    let root = temporary.path("repository");
    let mut repository = Repository::open(&root)?;
    let mut buffers = Buffers::new();
    let bytes: Vec<_> = (0..BLOCK_BYTES + 19).map(|n| (n % 251) as u8).collect();
    let content = buffers
        .publish(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &mut repository,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let path = object_path(&root, &content.query);
    let original = fs::read(&path)?;
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    fs::write(&path, damaged)?;
    let mut output = Vec::new();
    assert!(matches!(
        buffers.copy_to(
            &mut repository,
            content,
            &mut output,
            Limits::default(),
            |_| Control::Continue
        ),
        Err(Error::Protocol(gnunet_types::Error::Authentication))
    ));
    assert!(output.is_empty());
    fs::write(&path, &original)?;

    assert!(matches!(
        buffers.copy_to(
            &mut repository,
            content,
            &mut output,
            Limits::default(),
            |progress| {
                if progress.plaintext_bytes >= BLOCK_BYTES as u64 {
                    Control::Cancel
                } else {
                    Control::Continue
                }
            }
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(output, bytes[..BLOCK_BYTES]);
    output.clear();
    {
        let mut source = CountedSource {
            repository: &mut repository,
            reads: 0,
        };
        assert!(matches!(
            buffers.copy_to(
                &mut source,
                content,
                &mut output,
                Limits {
                    max_file_bytes: content.size - 1,
                    ..Limits::default()
                },
                |_| Control::Continue,
            ),
            Err(Error::Limit)
        ));
        assert_eq!(source.reads, 0);
    }
    assert!(output.is_empty());

    let outside = temporary.path("untouched-block");
    fs::write(&outside, &original)?;
    fs::remove_file(&path)?;
    symlink(&outside, &path)?;
    assert!(matches!(
        buffers.copy_to(
            &mut repository,
            content,
            &mut output,
            Limits::default(),
            |_| Control::Continue
        ),
        Err(Error::Io(_))
    ));
    assert!(output.is_empty());
    assert_eq!(fs::read(&outside)?, original);
    let alias = temporary.path("repository-alias");
    symlink(&root, &alias)?;
    assert!(matches!(Repository::open(alias), Err(Error::Io(_))));
    Ok(())
}
