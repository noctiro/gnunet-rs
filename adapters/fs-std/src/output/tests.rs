#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check actual authenticated output and filesystem safety boundaries"
)]
use super::*;
use crate::{BlockSink, Insert};
use gnunet_fs::content::{BLOCK_BYTES, EncodedNode, NodeRef};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Cleanup(std::path::PathBuf);
impl Cleanup {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct Blocks {
    rows: Vec<([u8; 64], Vec<u8>)>,
    data_reads: usize,
    corrupt_second: bool,
}
impl BlockSink for Blocks {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> Result<Insert> {
        self.rows.push((
            encoded.block().key().query,
            encoded.block().bytes().to_vec(),
        ));
        Ok(Insert::Created(crate::Retention::Volatile))
    }
}
impl BlockSource for Blocks {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> Result<usize> {
        let bytes = &self
            .rows
            .iter()
            .find(|row| row.0 == request.key().query)
            .ok_or(Error::Corrupt)?
            .1;
        output
            .get_mut(..bytes.len())
            .ok_or(Error::Corrupt)?
            .copy_from_slice(bytes);
        if request.node().level() == 0 {
            self.data_reads += 1;
            if self.corrupt_second && self.data_reads == 2 {
                output[bytes.len() - 1] ^= 1;
            }
        }
        Ok(bytes.len())
    }
}
fn input() -> Vec<u8> {
    (0..BLOCK_BYTES + 1).map(|n| (n % 251) as u8).collect()
}
fn published(bytes: &[u8]) -> Result<(Content, Blocks)> {
    let mut source = Blocks::default();
    let file = Buffers::new().publish(
        &mut &bytes[..],
        bytes.len() as u64,
        &mut source,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((file.content, source))
}
#[test]
#[cfg(unix)]
fn revalidation_restarts_ctime_only_but_bounds_continuous_metadata_changes() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = Cleanup::new()?;
    let path = root.0.join("plain");
    let bytes = input();
    fs::write(&path, &bytes)?;
    File::open(&path)?.sync_all()?;
    let output = OutputDir::open(&root.0)?;
    let identity = output.inspect_file("plain")?.ok_or(Error::Corrupt)?;
    let mut cache = crate::Repository::open(root.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let content = buffers
        .publish(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &mut cache,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let mut changed = false;
    let mut mutation_error = None;
    let verified = output.revalidate_file(
        "plain",
        content,
        identity,
        None,
        &mut buffers,
        &mut cache,
        Limits::default(),
        |_| {
            if !changed {
                changed = true;
                if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o400)) {
                    mutation_error = Some(error);
                    return Control::Cancel;
                }
            }
            Control::Continue
        },
    );
    if let Some(error) = mutation_error {
        return Err(error.into());
    }
    let verified = verified.map_err(|error| io::Error::other(error.to_string()))?;
    assert_eq!(verified.source_attempts, 2);
    assert_eq!(verified.read.verified.content(), content);
    assert_eq!(verified.identity, identity);
    assert_eq!(fs::read(&path)?, bytes);

    let mut mode = 0o600;
    let refused = output.revalidate_file(
        "plain",
        content,
        identity,
        None,
        &mut buffers,
        &mut cache,
        Limits::default(),
        |_| {
            if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(mode)) {
                mutation_error = Some(error);
                return Control::Cancel;
            }
            mode ^= 0o200;
            Control::Continue
        },
    );
    if let Some(error) = mutation_error {
        return Err(error.into());
    }
    let refused = match refused {
        Err(failure) => failure,
        Ok(_) => return Err(Error::Corrupt),
    };
    assert_eq!(refused.source_attempts(), 2);
    assert!(matches!(&refused.operation, Error::SourceChanged));
    let previous = refused.previous.as_ref().ok_or(Error::Corrupt)?;
    assert_eq!(previous.source_attempts(), 1);
    assert!(matches!(&previous.operation, Error::SourceChanged));
    assert!(previous.fence.is_some());
    assert!(refused.fence.is_some());
    Ok(())
}
#[test]
fn nested_authenticated_output_stays_on_the_original_directory_descriptor() -> Result<()> {
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    fs::create_dir(&selected)?;
    let mut output = OutputDir::open(&selected)?;
    let moved = root.0.join("original");
    fs::rename(&selected, &moved)?;
    fs::create_dir(&selected)?;
    let bytes = input();
    let (content, mut source) = published(&bytes)?;
    let read = output.write_file(
        "a/b/file.bin",
        &mut source,
        content,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(read.verified.content(), content);
    assert_eq!(read.progress.plaintext_bytes, bytes.len() as u64);
    assert_eq!(fs::read(moved.join("a/b/file.bin"))?, bytes);
    assert!(!selected.join("a").exists());
    assert_eq!(fs::read_dir(moved.join("a/b"))?.count(), 1);
    Ok(())
}
#[test]
#[cfg(unix)]
fn unsafe_names_symlinks_and_existing_targets_leave_all_sentinels_unchanged() -> Result<()> {
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    let outside = root.0.join("outside");
    fs::create_dir(&selected)?;
    fs::create_dir(&outside)?;
    fs::write(selected.join("existing"), b"keep-existing")?;
    fs::write(outside.join("sentinel"), b"keep-outside")?;
    std::os::unix::fs::symlink(&outside, selected.join("escape"))?;
    std::os::unix::fs::symlink(outside.join("sentinel"), selected.join("final-link"))?;
    let (content, mut source) = published(b"authenticated")?;
    let mut output = OutputDir::open(&selected)?;
    let mut buffers = Buffers::new();
    for name in [
        "/absolute",
        "../outside/sentinel",
        "safe/../bad",
        "C:/bad",
        "C:bad",
        "a/C:bad",
        "a\\b",
        "nul\0bad",
        ".",
        "a//b",
        "a/",
    ] {
        assert!(matches!(
            output.write_file(
                name,
                &mut source,
                content,
                &mut buffers,
                Limits::default(),
                |_| Control::Continue
            ),
            Err(Error::Protocol(gnunet_types::Error::InvalidInput))
        ));
    }
    for name in ["escape/sentinel", "final-link", "existing"] {
        assert!(
            output
                .write_file(
                    name,
                    &mut source,
                    content,
                    &mut buffers,
                    Limits::default(),
                    |_| Control::Continue
                )
                .is_err()
        );
    }
    assert_eq!(fs::read(selected.join("existing"))?, b"keep-existing");
    assert_eq!(fs::read(outside.join("sentinel"))?, b"keep-outside");
    assert!(!selected.join("safe").exists());
    assert!(!selected.join("a").exists());
    assert_eq!(source.data_reads, 0);
    assert_eq!(fs::read_dir(&outside)?.count(), 1);
    Ok(())
}
#[test]
fn failed_authentication_and_cancelled_prefix_never_publish_or_leave_own_temporary() -> Result<()> {
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    fs::create_dir(&selected)?;
    fs::write(selected.join("sentinel"), b"keep")?;
    let bytes = input();
    let (content, mut source) = published(&bytes)?;
    source.corrupt_second = true;
    let mut output = OutputDir::open(&selected)?;
    let mut buffers = Buffers::new();
    assert!(
        output
            .write_file(
                "partial/corrupt",
                &mut source,
                content,
                &mut buffers,
                Limits::default(),
                |_| Control::Continue
            )
            .is_err()
    );
    assert!(!selected.join("partial/corrupt").exists());
    assert_eq!(fs::read_dir(selected.join("partial"))?.count(), 0);
    source.corrupt_second = false;
    source.data_reads = 0;
    let mut output = OutputDir::open(&selected)?;
    let final_name = temporary_name(0);
    let mut saw_prefix = false;
    let result = output.write_file(
        &final_name,
        &mut source,
        content,
        &mut buffers,
        Limits::default(),
        |progress| {
            assert!(!selected.join(&final_name).exists());
            if progress.plaintext_bytes != 0 {
                saw_prefix = true;
                Control::Cancel
            } else {
                Control::Continue
            }
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(saw_prefix);
    assert!(!selected.join(final_name).exists());
    assert_eq!(fs::read(selected.join("sentinel"))?, b"keep");
    assert!(fs::read_dir(&selected)?.all(|entry| {
        entry.is_ok_and(|entry| entry.file_name() == "sentinel" || entry.file_name() == "partial")
    }));
    Ok(())
}

#[cfg(feature = "service")]
#[tokio::test(flavor = "current_thread")]
async fn network_download_cache_uses_the_same_owned_no_clobber_commit() -> Result<()> {
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    fs::create_dir(&selected)?;
    let bytes = input();
    let mut repository = crate::Repository::open(root.0.join("repository"))?;
    let content = Buffers::new()
        .publish(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &mut repository,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let mut output = OutputDir::open(&selected)?;
    let mut buffers = Buffers::new();
    let options =
        crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::from_micros(u64::MAX));
    let read = output
        .download_file(
            "a/b/download.bin",
            gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
            content,
            &mut buffers,
            Some(&mut repository),
            options,
            |_| Control::Continue,
        )
        .await?;
    assert_eq!(read.verified.content(), content);
    assert_eq!(read.progress.plaintext_bytes, bytes.len() as u64);
    assert_eq!(fs::read(selected.join("a/b/download.bin"))?, bytes);
    assert_eq!(fs::read_dir(selected.join("a/b"))?.count(), 1);
    assert!(matches!(
        output
            .download_file(
                "a/b/download.bin",
                gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
                content,
                &mut buffers,
                Some(&mut repository),
                options,
                |_| Control::Continue,
            )
            .await,
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(selected.join("a/b/download.bin"))?, bytes);
    Ok(())
}

#[cfg(feature = "service")]
#[tokio::test(flavor = "current_thread")]
async fn network_failure_and_dropped_pending_download_remove_only_the_owned_temporary() -> Result<()>
{
    use std::{future::Future, task::Poll};
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    fs::create_dir(&selected)?;
    fs::write(selected.join("sentinel"), b"keep")?;
    let (content, _) = published(b"authenticated")?;
    let mut output = OutputDir::open(&selected)?;
    let mut buffers = Buffers::new();
    let mut options =
        crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::from_micros(u64::MAX));
    options.io_slice_bytes = 0;
    let refused = output
        .download_file(
            "refused",
            gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
            content,
            &mut buffers,
            None,
            options,
            |_| Control::Continue,
        )
        .await;
    assert!(matches!(
        refused,
        Err(Error::Transfer(error))
            if matches!(*error, crate::network::Error::Protocol(gnunet_types::Error::InvalidInput))
    ));
    assert!(!selected.join("refused").exists());
    assert_eq!(fs::read_dir(&selected)?.count(), 1);
    options.io_slice_bytes = 1;
    let mut waiting = Box::pin(output.download_file(
        "pending",
        gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
        content,
        &mut buffers,
        None,
        options,
        |_| Control::Continue,
    ));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(!selected.join("pending").exists());
    assert_eq!(fs::read_dir(&selected)?.count(), 2);
    drop(waiting);
    assert!(!selected.join("pending").exists());
    assert_eq!(fs::read_dir(&selected)?.count(), 1);
    assert_eq!(fs::read(selected.join("sentinel"))?, b"keep");
    Ok(())
}
#[test]
fn commit_intent_observer_failure_vetoes_link_and_retains_real_read_receipt() -> Result<()> {
    let directory = Cleanup::new()?;
    let mut output = OutputDir::open(&directory.0)?;
    let (content, mut source) = published(b"authenticated")?;
    let mut events = Vec::new();
    let result = output.write_file_observed(
        "veto",
        &mut source,
        content,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
        None,
        |event| {
            let code = match event {
                OutputObservation::TempOwned(_) => 0,
                OutputObservation::CommitIntent { .. } => 1,
                OutputObservation::FileCommitted { .. } => 2,
                OutputObservation::Cleanup { .. } => 3,
            };
            events.push(code);
            if code == 1 {
                Err("intent storage failed")
            } else {
                Ok(())
            }
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err(Error::Corrupt),
    };
    assert_eq!(error.stage, CommitStage::NotLinked);
    assert!(error.operation.is_none());
    assert_eq!(error.observer, Some("intent storage failed"));
    assert!(error.cleanup.is_none());
    assert_eq!(
        error.receipt.map(|read| read.verified.content()),
        Some(content)
    );
    assert_eq!(events, vec![0, 1]);
    assert!(!directory.0.join("veto").exists());
    assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
    Ok(())
}
#[test]
fn committed_observer_failure_preserves_durable_output_and_exact_cleanup() -> Result<()> {
    let directory = Cleanup::new()?;
    let mut output = OutputDir::open(&directory.0)?;
    let (content, mut source) = published(b"authenticated")?;
    let result = output.write_file_observed(
        "committed",
        &mut source,
        content,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
        None,
        |event| {
            if matches!(event, OutputObservation::FileCommitted { .. }) {
                Err("commit record failed")
            } else {
                Ok(())
            }
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err(Error::Corrupt),
    };
    let barrier = Directory::open(&directory.0)?.sync()?;
    assert_eq!(error.stage, CommitStage::FileSynchronized(barrier));
    assert!(error.operation.is_none());
    assert_eq!(error.observer, Some("commit record failed"));
    assert!(error.cleanup.is_none());
    assert_eq!(
        error.receipt.map(|read| read.verified.content()),
        Some(content)
    );
    assert_eq!(fs::read(directory.0.join("committed"))?, b"authenticated");
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}
#[cfg(feature = "service")]
#[tokio::test(flavor = "current_thread")]
async fn staged_range_retains_absolute_offsets_and_revalidates_only_selected_bytes() -> Result<()> {
    use crate::network::range::{Completion, Options};
    use std::{
        convert::Infallible,
        io::{Seek, SeekFrom, Write},
    };
    let root = Cleanup::new()?;
    let selected = root.0.join("selected");
    fs::create_dir(&selected)?;
    let mut output = OutputDir::open(&selected)?;
    let owner = [73; 32];
    let mut staging = output
        .create_owned_directory("stage", owner)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let parent_id = output.identity()?;
    let stage_id = staging.identity()?;
    let moved = root.0.join("original");
    fs::rename(&selected, &moved)?;
    fs::create_dir(&selected)?;
    fs::write(selected.join("sentinel"), b"foreign")?;
    let bytes = input();
    let mut cache = crate::Repository::open(root.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let content = buffers
        .publish(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &mut cache,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let selection = BLOCK_BYTES as u64 - 5..bytes.len() as u64;
    let options = Options {
        download: crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::NEVER),
        native_deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
    };
    let mut committed = false;
    let read = output
        .download_range_observed(
            "range.bin",
            &mut staging,
            gnunet_client_host::EndpointSource::unix(root.0.join("absent.sock")),
            content,
            selection.clone(),
            &mut buffers,
            Some(&mut cache),
            options,
            |_| Control::Continue,
            |event| {
                if let OutputObservation::FileCommitted {
                    temporary,
                    final_parent,
                    ..
                } = event
                {
                    assert_eq!(temporary.parent, stage_id);
                    assert_eq!(final_parent, parent_id);
                    committed = true;
                }
                Ok::<_, Infallible>(())
            },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    assert!(committed);
    assert_eq!(read.delivered_bytes, 6);
    assert_eq!(
        read.destination,
        crate::network::range::Destination::SinkCompleted
    );
    assert!(matches!(read.completion, Completion::Verified(proof) if proof.range() == selection));
    let actual = fs::read(moved.join("range.bin"))?;
    assert_eq!(actual.len(), bytes.len());
    assert!(
        actual[..selection.start as usize]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        &actual[selection.start as usize..],
        &bytes[selection.start as usize..]
    );
    assert!(!selected.join("range.bin").exists());
    assert_eq!(fs::read(selected.join("sentinel"))?, b"foreign");
    assert_eq!(fs::read_dir(moved.join("stage"))?.count(), 1);
    drop(staging);
    let _stage = output
        .attach_owned_directory("stage", owner, Some(stage_id))
        .map_err(|error| io::Error::other(error.to_string()))?;
    let identity = output.inspect_file("range.bin")?.ok_or(Error::Corrupt)?;
    // A change outside the selected interval does not acquire or invalidate
    // a whole-file claim: only the actual selected bytes are compared.
    let held = fs::OpenOptions::new()
        .write(true)
        .open(moved.join("range.bin"))?;
    let mut mutation = &held;
    mutation.seek(SeekFrom::Start(0))?;
    mutation.write_all(b"X")?;
    let reread = output
        .revalidate_range(
            "range.bin",
            content,
            selection.clone(),
            identity,
            Some(parent_id),
            &mut buffers,
            &mut cache,
            Limits::default(),
            |_| Control::Continue,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    assert_eq!(reread.read.delivered_bytes, 6);
    assert_eq!(
        reread.read.destination,
        crate::network::range::Destination::ExistingFileCompared
    );
    mutation.seek(SeekFrom::Start(selection.start))?;
    mutation.write_all(b"!")?;
    let refused = output.revalidate_range(
        "range.bin",
        content,
        selection,
        identity,
        Some(parent_id),
        &mut buffers,
        &mut cache,
        Limits::default(),
        |_| Control::Continue,
    );
    assert!(
        matches!(refused, Err(error) if matches!(error.operation, Error::SourceChanged) && error.receipt.is_none())
    );
    assert!(moved.join("range.bin").exists());
    Ok(())
}
