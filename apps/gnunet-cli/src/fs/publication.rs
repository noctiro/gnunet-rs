//! Explicit native indexed, keyword and namespace storage publication.
use super::service::{datastore_client, duration, target};
use gnunet::{
    crypto::gns::EdkeySecret,
    datastore_host::{Instance, ReservationSlot, Slot},
    fs::{Keywords, Limits as UriLimits, Uri, metadata},
    fs_host::{
        Buffers, Control,
        ipc::EndpointSource,
        network::ublock::{PublishedUblocks, UblockFailure, UblockOptions, UblockProgress},
    },
};
use std::{
    error::Error,
    ffi::OsStr,
    fmt::Write as _,
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

fn write_row(out: &mut super::Output<'_, impl Write>, row: &serde_json::Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, row).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
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
    out: &mut super::Output<'_, impl Write>,
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
    out: &mut super::Output<'_, impl Write>,
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
    out: &mut super::Output<'_, impl Write>,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::keyword_arguments(args, true)?;
    let args = parsed.positional;
    let interval = duration(args.get(3))?;
    let mut metadata =
        super::publish::settings::RecordMetadata::new(parsed.manual, parsed.compression)?;
    let metadata = metadata.plan()?;
    let Uri::Keywords(keywords) =
        Uri::parse(crate::argument::wire_bytes(args[1])?, UriLimits::default())?
    else {
        return Err("fs publish-keywords requires a KSK URI".into());
    };
    let uri = Uri::parse(crate::argument::wire_bytes(args[2])?, UriLimits::default())?;
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
            let result = store_keywords(source, keywords, uri, metadata.as_ref(), options, |_| {
                Control::Continue
            })
            .await?;
            ublock_result(result, "keywords", &encoded, out)
        })
}

pub(super) async fn store_keywords(
    source: EndpointSource,
    keywords: Keywords<'_>,
    uri: Uri<'_>,
    metadata: Option<&metadata::Plan<'_>>,
    options: UblockOptions,
    control: impl FnMut(UblockProgress) -> Control,
) -> Result<Result<PublishedUblocks, Box<UblockFailure>>, gnunet::datastore_host::Error> {
    let mut identity = Instance::new();
    let mut wire = vec![0; 65535];
    let mut slots = [Slot::new(&mut wire)];
    let mut reservations = [ReservationSlot::default(); 1];
    let client = datastore_client(&mut identity, &mut slots, &mut reservations, source)?;
    Ok(Buffers::new()
        .store_keywords(client, keywords, uri, metadata, options, control)
        .await)
}

pub(super) fn namespace(
    args: &[impl AsRef<OsStr>],
    out: &mut super::Output<'_, impl Write>,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::metadata_arguments(args, 5, 6, &[])?;
    let args = parsed.positional;
    let interval = duration(args.get(5))?;
    let secret = seed(Path::new(args[1]))?;
    let label = crate::argument::wire_bytes(args[2])?;
    let update = crate::argument::wire_bytes(args[3])?;
    let uri = Uri::parse(crate::argument::wire_bytes(args[4])?, UriLimits::default())?;
    let encoded = uri_bytes(uri)?;
    let source = EndpointSource::unix(Path::new(args[0]).to_path_buf());
    let options = UblockOptions::new(
        target(&source, interval)?,
        parsed.publication.select(source.clock().as_ref())?,
    );
    let mut metadata =
        super::publish::settings::RecordMetadata::new(parsed.manual, parsed.compression)?;
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
