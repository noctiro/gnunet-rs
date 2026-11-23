//! Native GNUnet CHK and LOC downloads with anchored, authenticated output.
use super::{Result, configured, output, service};
use crate::fs::{Output, stop, task};
use gnunet::{
    fs::{Content, Limits, Location, Uri},
    fs_host::{
        Buffers, Control, IncompleteOutput, OutputDir,
        ipc::EndpointSource,
        network::{DownloadOptions, tree_download::TreeDownloadOptions},
    },
};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::Instant;

const BINARY: &[u8] = b"gnunet-download";

enum Root {
    File(Content),
    Location(Location),
}

impl Root {
    fn parse(bytes: &[u8]) -> std::result::Result<Self, Box<dyn Error>> {
        match Uri::parse(bytes, Limits::default())? {
            Uri::Content(content) => Ok(Self::File(content)),
            Uri::Location(location) => Ok(Self::Location(location)),
            _ => Err("download requires a CHK or LOC URI".into()),
        }
    }
}

struct Download {
    root: Root,
    output: PathBuf,
    anonymity: u32,
    local_only: bool,
    recursive: bool,
    incomplete: IncompleteOutput,
    file_parallelism: NonZeroU32,
    request_parallelism: NonZeroU32,
    verbose: u32,
}

pub(crate) fn run() -> Result {
    let anonymity = Target::new(1);
    let delete = Target::new(0);
    let local = Target::new(0);
    let output_name = Target::new(None::<Vec<u8>>);
    let downloads = Target::new(16);
    let requests = Target::new(4092);
    let recursive = Target::new(0);
    let verbose = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::uint(
        b'a',
        b"anonymity",
        b"LEVEL",
        b"Set receiver anonymity",
        anonymity.clone(),
    ));
    options.add(helpers::flag(
        b'D',
        b"delete-incomplete",
        b"Remove incomplete output on cancellation",
        delete.clone(),
    ));
    options.add(helpers::flag(
        b'n',
        b"no-network",
        b"Retrieve only from the local peer",
        local.clone(),
    ));
    options.add(helpers::string(
        b'o',
        b"output",
        b"FILENAME",
        b"Set the download output path",
        output_name.clone(),
    ));
    options.add(helpers::uint(
        b'p',
        b"parallelism",
        b"DOWNLOADS",
        b"Set a positive upper bound on active downloads",
        downloads.clone(),
    ));
    options.add(helpers::uint(
        b'r',
        b"request-parallelism",
        b"REQUESTS",
        b"Set a positive upper bound on outstanding block requests",
        requests.clone(),
    ));
    options.add(helpers::flag(
        b'R',
        b"recursive",
        b"Download an authenticated GNUnet directory recursively",
        recursive.clone(),
    ));
    options.add(helpers::verbose(verbose.clone()));
    let Some((prepared, clock)) = configured::prepare(
        BINARY,
        b"Download a file or directory identified by a GNUnet CHK or LOC URI",
        options,
    )?
    else {
        return Ok(());
    };
    let main = prepared.main();
    let [uri] = main.arguments else {
        return Err("specify exactly one CHK or LOC URI".into());
    };
    let request_parallelism =
        NonZeroU32::new(requests.get()?).ok_or("parallelism limits must be positive")?;
    let file_parallelism =
        NonZeroU32::new(downloads.get()?).ok_or("parallelism limits must be positive")?;
    let output_name = output_name
        .get()?
        .ok_or("specify the destination with -o/--output")?;
    let plan = Download {
        root: Root::parse(uri)?,
        output: gnunet_native::os_bytes::decode_owned(output_name)?.into(),
        anonymity: anonymity.get()?,
        local_only: local.get()? != 0,
        recursive: recursive.get()? != 0,
        incomplete: if delete.get()? == 0 {
            IncompleteOutput::Keep
        } else {
            IncompleteOutput::Delete
        },
        file_parallelism,
        request_parallelism,
        verbose: verbose.get()?,
    };
    output::with_stdout("gnunet-download", false, |out| {
        configured::run(main.config, clock, [b"fs"], |[source]| {
            transfer(plan, source, out)
        })
    })
}

async fn transfer(
    plan: Download,
    source: EndpointSource,
    out: &mut Output<'_, impl Write>,
) -> Result {
    let interval = service::DEFAULT_INTERVAL_MICROS;
    let started = Instant::now();
    let hard = started
        .checked_add(Duration::from_micros(interval))
        .ok_or("download deadline overflow")?;
    out.deadline(hard);
    let deadline = service::target(&source, interval)?;
    let (content, mut options) = match plan.root {
        Root::File(content) => (content, DownloadOptions::new(deadline)),
        Root::Location(location) => (
            location.content(),
            DownloadOptions::location(location, deadline),
        ),
    };
    options.native_deadline = Some(hard);
    options.anonymity = plan.anonymity;
    options.local_only = plan.local_only;
    options.request_parallelism = plan.request_parallelism;
    let (parent, name) = task::destination(&plan.output)?;
    let mut directory = OutputDir::open(parent)?;
    let mut buffers = Buffers::new();
    let mut signals = stop::StopEvents::new()?;
    let cancelled = Cell::new(false);
    let mut progress = DownloadProgress {
        path: &plan.output,
        verbose: plan.verbose,
        last: started,
        error: None,
    };
    let result = {
        let work = async {
            if plan.recursive {
                let mut tree = TreeDownloadOptions::new(options);
                tree.file_parallelism = plan.file_parallelism;
                let done = directory
                    .download_tree_resumable(
                        name,
                        source,
                        content,
                        &mut buffers,
                        tree,
                        plan.incomplete,
                        |step| progress.control(out, &cancelled, step.file_bytes),
                    )
                    .await?;
                Ok::<u128, Box<dyn Error>>(done.progress.file_bytes)
            } else {
                let done = directory
                    .download_resumable(
                        name,
                        source,
                        content,
                        &mut buffers,
                        options,
                        plan.incomplete,
                        |step| progress.control(out, &cancelled, u128::from(step.plaintext_bytes)),
                    )
                    .await?;
                Ok(u128::from(done.progress.plaintext_bytes))
            }
        };
        let mut work = std::pin::pin!(work);
        poll_fn(|cx| {
            if signals.poll(cx) {
                cancelled.set(true);
            }
            work.as_mut().poll(cx)
        })
        .await
    };
    let result = match (result, progress.error) {
        (result, None) => result,
        (result, Some(output)) => Err(Box::new(ProgressFailure {
            operation: result.err(),
            output,
        }) as Box<dyn Error>),
    };
    signals.finish(result.and_then(|bytes| {
        out.cleanup()?;
        let elapsed = started.elapsed().as_micros().max(1);
        let rate = bytes.saturating_mul(1_000_000) / elapsed;
        writeln!(
            out,
            "Downloading `{}' done ({rate} B/s).",
            plan.output.display()
        )?;
        Ok(())
    }))
}

struct DownloadProgress<'a> {
    path: &'a Path,
    verbose: u32,
    last: Instant,
    error: Option<io::Error>,
}

impl DownloadProgress<'_> {
    fn control(&mut self, out: &mut impl Write, cancelled: &Cell<bool>, bytes: u128) -> Control {
        if cancelled.get() || self.error.is_some() {
            return Control::Cancel;
        }
        let now = Instant::now();
        if self.verbose != 0 && now.duration_since(self.last) >= Duration::from_secs(1) {
            self.last = now;
            self.error = writeln!(
                out,
                "Downloading `{}' at {bytes} bytes",
                self.path.display()
            )
            .and_then(|()| out.flush())
            .err();
            if self.error.is_some() {
                return Control::Cancel;
            }
        }
        Control::Continue
    }
}

#[derive(Debug)]
struct ProgressFailure {
    operation: Option<Box<dyn Error>>,
    output: io::Error,
}

impl fmt::Display for ProgressFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "download progress output: {}", self.output)?;
        if let Some(operation) = &self.operation {
            write!(f, " ({operation})")?;
        }
        Ok(())
    }
}

impl Error for ProgressFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.operation.as_deref().or(Some(&self.output))
    }
}
