//! Native recursive directory operations over official service sockets.
use super::service::{duration, target};
use gnunet::{
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers, Control, OutputDir,
        ipc::EndpointSource,
        network::{DownloadOptions, tree_download::TreeDownloadOptions},
    },
};
use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

fn row(out: &mut impl Write, value: &serde_json::Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}

pub(super) fn publish(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    super::publish::run(
        args,
        super::publish::Mode {
            indexed: false,
            tree: true,
        },
        out,
    )
}
pub(super) fn publish_indexed(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    super::publish::run(
        args,
        super::publish::Mode {
            indexed: true,
            tree: true,
        },
        out,
    )
}

pub(super) fn fetch(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let interval = duration(args.get(3))?;
    let source = EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    let (content, transfer) = match Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())? {
        Uri::Content(content) => (content, DownloadOptions::new(deadline)),
        Uri::Location(location) => (
            location.content(),
            DownloadOptions::location(location, deadline),
        ),
        _ => return Err("fs fetch-tree requires a resolved directory CHK or LOC URI".into()),
    };
    let destination = Path::new(args[2].as_ref());
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = destination
        .file_name()
        .ok_or("fs fetch-tree requires a new directory name")?;
    let mut output = OutputDir::open(parent)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        match output.download_tree(name, source, content, &mut Buffers::new(), None, TreeDownloadOptions::new(transfer), |_| Control::Continue).await {
            Ok(done) => {
                row(out, &serde_json::json!({
                    "event":"fs_tree_download_complete", "files":done.progress.files_committed,
                    "directories":done.progress.directories_verified, "bytes":done.progress.file_bytes,
                    "entries":done.walk.entries, "scheduled_content_bytes":done.walk.content_bytes,
                }))?;
                Ok(())
            }
            Err(error) => {
                let text = error.path.to_str();
                let bytes = text.is_none().then_some(error.path.as_os_str().as_bytes());
                let _output = row(out, &serde_json::json!({
                    "event":"fs_tree_download_failed", "path":text, "path_bytes":bytes,
                    "root_created":error.progress.root_created,
                    "directories_created":error.progress.directories_created,
                    "directories_verified":error.progress.directories_verified,
                    "files_committed":error.progress.files_committed, "bytes":error.progress.file_bytes,
                    "error":error.to_string(),
                    "interruption":error.interruption.as_ref().map(ToString::to_string),
                    "namespace_cleanup":error.namespace_cleanup.as_ref().map(ToString::to_string),
                }));
                Err(Box::<dyn Error>::from(error))
            }
        }
    })
}
