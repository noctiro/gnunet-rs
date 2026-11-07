//! Explicit actual native range observation; no download output or cache.
use super::service::{duration, target};
use gnunet::{
    crypto::Entropy,
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers, Control,
        ipc::EndpointSource,
        network::{self, DownloadOptions, probe},
    },
    types::Error as ProtocolError,
};
use serde_json::json;
use std::{
    error::Error,
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

struct EntropySource(File);
impl Entropy for EntropySource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), ProtocolError> {
        self.0
            .read_exact(output)
            .map_err(|_| ProtocolError::Entropy)
    }
}

pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = match args.get(2) {
        Some(_) => duration(args.get(2))?,
        None => 5_000_000,
    };
    let uri = Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())?;
    let source = EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    let (content, transfer) = match uri {
        Uri::Content(content) => (content, DownloadOptions::new(deadline)),
        Uri::Location(location) => (
            location.content(),
            DownloadOptions::location(location, deadline),
        ),
        _ => return Err("FS probe requires a resolved CHK or signed LOC URI".into()),
    };
    let leaf = match args.get(3) {
        Some(raw) => raw
            .as_ref()
            .to_str()
            .ok_or("leaf ordinal must be UTF-8 digits")?
            .parse::<u64>()?,
        None => probe::sample_leaf(content, &mut EntropySource(File::open("/dev/urandom")?))?,
    };
    let observed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Buffers::new().probe(
            source,
            content,
            leaf,
            probe::Options::from(transfer),
            |_| Control::Continue,
        ));
    let row = match &observed {
        Ok(actual) => {
            let progress = actual.progress();
            let range = actual.range();
            json!({"event":"fs_probe_observed","leaf":actual.leaf(),"range_start":range.start,"range_end":range.end,
                "bytes":progress.plaintext_bytes,"blocks":progress.blocks,"encoded_bytes":progress.encoded_bytes,
                "queries_written":actual.queries_written(),"elapsed_us":actual.elapsed().0,"retired":actual.retired()})
        }
        Err(failure) => {
            let progress = failure.progress();
            let range = failure.range();
            let phase = match failure.cause() {
                network::Error::Deadline { .. } if failure.queries_written() > 0 => "inconclusive",
                network::Error::Deadline { .. } => "setup_deadline",
                network::Error::Cancelled(_) => "cancelled",
                _ => "error",
            };
            json!({"event":"fs_probe_interrupted","phase":phase,"cause":failure.cause().to_string(),"leaf":failure.leaf(),
                "range_start":range.as_ref().map(|v|v.start),"range_end":range.as_ref().map(|v|v.end),
                "bytes":progress.plaintext_bytes,"blocks":progress.blocks,"encoded_bytes":progress.encoded_bytes,
                "queries_written":failure.queries_written(),"last_checked_us":failure.last_checked().map(|v|v.as_micros()),"retired":failure.retired()})
        }
    };
    serde_json::to_writer(&mut *out, &row).map_err(io::Error::other)?;
    writeln!(out)?;
    observed
        .map(|_| ())
        .map_err(|failure| Box::new(failure) as Box<dyn Error>)
}
