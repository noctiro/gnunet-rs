//! Explicit native indexed, keyword and namespace storage publication.
use super::service::{datastore_client, duration, target};
use gnunet::{
    crypto::gns::EdkeySecret,
    datastore_host::{Instance, ReservationSlot, Slot},
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers, Control,
        ipc::EndpointSource,
        network::ublock::{PublishedUblocks, UblockFailure, UblockOptions},
    },
};
use std::{
    error::Error,
    ffi::OsStr,
    fmt::Write as _,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};
use zeroize::Zeroizing;

fn write_row(out: &mut impl Write, row: &serde_json::Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, row).map_err(io::Error::other)?;
    writeln!(out)
}
pub(super) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into String cannot fail.
        let _written = write!(&mut text, "{byte:02x}");
    }
    text
}
fn uri_bytes(uri: Uri<'_>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; uri.encoded_len()?];
    uri.encode(&mut bytes)?;
    Ok(bytes)
}
fn seed(path: &Path) -> Result<EdkeySecret, Box<dyn Error>> {
    // open_input rejects nonregular descriptors without waiting on a FIFO.
    let mut file = gnunet::fs_host::open_input(path)?;
    if file.metadata()?.len() != 32 {
        return Err("namespace seed must contain exactly 32 raw bytes".into());
    }
    let mut bytes = Zeroizing::new([0; 32]);
    file.read_exact(&mut bytes[..])?;
    let mut extra = Zeroizing::new([0; 1]);
    loop {
        match file.read(&mut extra[..]) {
            Ok(0) => break,
            Ok(_) => return Err("namespace seed must contain exactly 32 raw bytes".into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    // EdkeySecret erases its own input copy and retains a zeroizing seed.
    Ok(EdkeySecret::from_seed(*bytes))
}
fn ublock_result(
    result: Result<PublishedUblocks, Box<UblockFailure>>,
    operation: &str,
    uri: &[u8],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let target_uri = std::str::from_utf8(uri).ok();
    let target_uri_bytes = target_uri.is_none().then_some(uri);
    match result {
        Ok(done) => write_row(
            out,
            &serde_json::json!({
                "event": "fs_ublock_store_complete",
                "operation": operation,
                "target_uri": target_uri,
                "target_uri_bytes": target_uri_bytes,
                "acknowledged_terms": done.progress.accepted,
                "stored_bytes": done.progress.wire_bytes,
                "last_query": done.progress.last_query.as_ref().map(|query| hex(query)),
                "connection_cleanup": done.cleanup.as_ref().map(ToString::to_string),
            }),
        )
        .map_err(Into::into),
        Err(error) => {
            // Failure keeps the original typed cause even if output also fails.
            let _output = write_row(
                out,
                &serde_json::json!({
                    "event": "fs_ublock_store_failed",
                    "operation": operation,
                    "target_uri": target_uri,
                    "target_uri_bytes": target_uri_bytes,
                    "acknowledged_terms": error.progress.accepted,
                    "stored_bytes": error.progress.wire_bytes,
                    "last_acknowledged_query": error.progress.last_query.as_ref().map(|query| hex(query)),
                    "failed_index": error.failed_index,
                    "failed_query": error.query.as_ref().map(|query| hex(query)),
                    "error": error.to_string(),
                    "connection_cleanup": error.retirement_error.as_ref().map(ToString::to_string),
                }),
            );
            Err(error)
        }
    }
}

pub(super) fn indexed(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    super::publish::run(
        args,
        super::publish::Mode {
            indexed: true,
            tree: false,
        },
        out,
    )
}

pub(super) fn keywords(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::keyword_arguments(args, true)?;
    let args = parsed.positional;
    let interval = duration(args.get(3))?;
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    let Uri::Keywords(keywords) = Uri::parse(args[1].as_bytes(), UriLimits::default())? else {
        return Err("fs publish-keywords requires a KSK URI".into());
    };
    let uri = Uri::parse(args[2].as_bytes(), UriLimits::default())?;
    let encoded = uri_bytes(uri)?;
    let source = EndpointSource::unix(Path::new(args[0]).to_path_buf());
    let options = UblockOptions::new(
        target(&source, interval)?,
        parsed.publication.select(source.clock().as_ref())?,
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut identity = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [ReservationSlot::default(); 1];
            let client = datastore_client(&mut identity, &mut slots, &mut reservations, source)?;
            let result = Buffers::new()
                .store_keywords(client, keywords, uri, metadata.as_ref(), options, |_| {
                    Control::Continue
                })
                .await;
            ublock_result(result, "keywords", &encoded, out)
        })
}

pub(super) fn namespace(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::metadata_arguments(args, 5, 6, &[])?;
    let args = parsed.positional;
    let interval = duration(args.get(5))?;
    let secret = seed(Path::new(args[1]))?;
    let label = args[2].as_bytes();
    let update = args[3].as_bytes();
    let uri = Uri::parse(args[4].as_bytes(), UriLimits::default())?;
    let encoded = uri_bytes(uri)?;
    let source = EndpointSource::unix(Path::new(args[0]).to_path_buf());
    let options = UblockOptions::new(
        target(&source, interval)?,
        parsed.publication.select(source.clock().as_ref())?,
    );
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut identity = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [ReservationSlot::default(); 1];
            let client = datastore_client(&mut identity, &mut slots, &mut reservations, source)?;
            let result = Buffers::new()
                .store_namespace(
                    client,
                    &secret,
                    label,
                    update,
                    uri,
                    metadata.as_ref(),
                    options,
                    |_| Control::Continue,
                )
                .await;
            ublock_result(result, "namespace", &encoded, out)
        })
}
