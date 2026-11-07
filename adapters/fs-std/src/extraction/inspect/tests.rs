//! Actual local descriptor/probe/sink boundaries; no provider or publication is
//! replaced with a success receipt and no service connection is constructed.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions identify actual local descriptor fixture failures; filesystem and host errors remain returned to the test harness."
)]
use super::*;
use std::{
    error::Error as StdError,
    fs::OpenOptions,
    io::{Seek, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn StdError>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-inspect-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sparse_file_uses_shared_metadata_and_terms_without_payload_artifacts()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("Archive Title.html");
    let mut input = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    input.write_all(b"<html><title>Actual title</title></html>")?;
    input.set_len(1024 * 1024 * 1024)?;
    input.seek(std::io::SeekFrom::Start(17))?;
    let policy = Policy {
        max_probe_bytes: 64,
        ..Default::default()
    };
    let expected = file_keywords(&input, &path, policy, |_| Control::Continue)?;
    let mut extracted = None;
    let report = inspect_with_metadata(
        &path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            extracted = Some(object);
            Ok(())
        },
    )?;
    let extracted = extracted.ok_or("missing extraction")?;
    assert_eq!(extracted.keywords, expected);
    assert!(
        decoded(&extracted.metadata, policy)?
            .items()
            .any(|item| item.kind == 4 && item.text() == Some(b"Actual title"))
    );
    assert_eq!(report.source_bytes, 1024 * 1024 * 1024);
    assert_eq!(report.objects, 1);
    assert_eq!(input.stream_position()?, 17);
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}

#[test]
fn descriptor_tree_streams_original_names_and_only_root_manual_metadata()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    fs::create_dir(directory.0.join("nested"))?;
    fs::write(directory.0.join("a.txt"), b"plain")?;
    fs::write(
        directory.0.join("nested").join("b.html"),
        b"<title>Nested actual title</title>",
    )?;
    let mut manual = ManualMetadata::default();
    manual.push(b"title:Manual Root Annotation")?;
    let settings = MetadataSettings::default().with_manual(manual);
    let policy = Policy::default();
    let mut paths = Vec::new();
    let report = inspect_with_metadata(
        &directory.0,
        Limits::default(),
        policy,
        settings,
        |_| Control::Continue,
        |object| {
            let root_annotation = decoded(&object.metadata, policy)?
                .items()
                .any(|item| item.kind == 4 && item.text() == Some(b"Manual Root Annotation"));
            if root_annotation != object.relative.as_os_str().is_empty() {
                return Err(Error::Policy);
            }
            if object
                .keywords
                .iter()
                .any(|term| term == b"Manual Root Annotation")
            {
                return Err(Error::Policy);
            }
            paths.push(object.relative);
            Ok(())
        },
    )?;
    assert_eq!(
        paths,
        [
            PathBuf::new(),
            PathBuf::from("a.txt"),
            PathBuf::from("nested"),
            PathBuf::from("nested/b.html")
        ]
    );
    assert_eq!(
        (report.objects, report.files, report.directories),
        (4, 2, 2)
    );
    assert_eq!(fs::read_dir(&directory.0)?.count(), 2);
    Ok(())
}

#[test]
fn mutation_during_sink_delivery_is_partial_failure_and_not_complete_preview()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("actual.txt");
    fs::write(&path, b"original")?;
    let outcome = inspect_with_metadata(
        &path,
        Limits::default(),
        Policy::default(),
        MetadataSettings::default(),
        |_| Control::Continue,
        |_| {
            OpenOptions::new().write(true).open(&path)?.set_len(9)?;
            Ok(())
        },
    );
    let failure = match outcome {
        Ok(_) => return Err("changed source was reported complete".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.report.objects, 1);
    assert!(matches!(failure.cause, Error::SourceChanged));
    Ok(())
}
