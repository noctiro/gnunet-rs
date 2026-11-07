//! Managed namespace keys and real acknowledged update-graph publication.
use super::publication::hex;
use super::service::{datastore_client, duration, target};
use gnunet::{
    crypto::EddsaPublicKey,
    datastore_host::{Instance, ReservationSlot, Slot},
    fs::{Limits as UriLimits, Namespace, Uri},
    fs_host::{
        Buffers, Control,
        durable::store,
        ipc::EndpointSource,
        namespace::{
            graph::{Graph, Limits, StoredRecord},
            key::KeyFile,
        },
        network::ublock::UblockOptions,
    },
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};
fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}
fn sks(public: [u8; 32], label: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let uri = Uri::Namespace(Namespace::new(EddsaPublicKey::from_bytes(public), label)?);
    let mut output = vec![0; uri.encoded_len()?];
    uri.encode(&mut output)?;
    Ok(output)
}
fn view(out: &mut impl Write, record: StoredRecord<'_>) -> io::Result<()> {
    write!(
        out,
        "{{\"record\":{},\"identifier_bytes\":",
        record.id().index()
    )?;
    serde_json::to_writer(&mut *out, record.identifier()).map_err(io::Error::other)?;
    out.write_all(b",\"update_bytes\":")?;
    serde_json::to_writer(&mut *out, record.update()).map_err(io::Error::other)?;
    out.write_all(b",\"identifier\":")?;
    serde_json::to_writer(&mut *out, &std::str::from_utf8(record.identifier()).ok())
        .map_err(io::Error::other)?;
    out.write_all(b",\"update\":")?;
    serde_json::to_writer(&mut *out, &std::str::from_utf8(record.update()).ok())
        .map_err(io::Error::other)?;
    out.write_all(b",\"target_uri\":")?;
    serde_json::to_writer(&mut *out, &std::str::from_utf8(record.raw_uri()).ok())
        .map_err(io::Error::other)?;
    out.write_all(b",\"target_uri_bytes\":")?;
    serde_json::to_writer(&mut *out, record.raw_uri()).map_err(io::Error::other)?;
    out.write_all(b",\"selected_metadata_wire_bytes\":")?;
    serde_json::to_writer(&mut *out, &record.metadata()).map_err(io::Error::other)?;
    out.write_all(b"}")
}
pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let key = KeyFile::create(Path::new(args[0].as_ref()))?;
    // If graph creation later fails, the already durable generated key remains
    // an actual known artifact, rather than being silently deleted or replaced.
    row(
        out,
        &json!({"event":"fs_namespace_key_created","public_key":hex(&key.public_key())}),
    )?;
    let graph = Graph::create(
        Path::new(args[1].as_ref()),
        key.public_key(),
        Limits::default(),
        store::Limits::default(),
    )?;
    let uri = sks(key.public_key(), b"")?;
    row(
        out,
        &json!({"event":"fs_namespace_created","public_key":hex(graph.namespace()),"empty_identifier_uri":std::str::from_utf8(&uri).ok(),"records":graph.record_count()}),
    )?;
    Ok(())
}
pub(super) fn list(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let key = KeyFile::open(Path::new(args[0].as_ref()))?;
    let mut graph = Graph::open(
        Path::new(args[1].as_ref()),
        key.public_key(),
        Limits::default(),
        store::Limits::default(),
    )?;
    let count = graph.record_count();
    let mut ids = Vec::new();
    ids.try_reserve_exact(count)?;
    match args.get(2) {
        Some(identifier) => ids.extend(graph.children(identifier.as_ref().as_bytes())),
        None => {
            for id in graph.roots()? {
                let identifier = graph
                    .record_identifier(id)
                    .ok_or("namespace root record missing")?;
                for child in graph.children(identifier) {
                    if ids.len() == count {
                        return Err("namespace child index exceeds accepted records".into());
                    }
                    ids.push(child);
                }
            }
        }
    }
    out.write_all(b"{\"event\":\"fs_namespace_updateable\",\"public_key\":")?;
    serde_json::to_writer(&mut *out, &hex(graph.namespace()))?;
    out.write_all(b",\"selection\":")?;
    serde_json::to_writer(
        &mut *out,
        if args.get(2).is_some() {
            "children"
        } else {
            "minimum_reachable_roots"
        },
    )?;
    write!(
        out,
        ",\"records_total\":{},\"retained_bytes\":{},\"records\":[",
        count,
        graph.retained_bytes()
    )?;
    for (index, id) in ids.into_iter().enumerate() {
        let record = graph
            .record(id)?
            .ok_or("namespace selected record missing")?;
        if index != 0 {
            out.write_all(b",")?;
        }
        view(out, record)?;
    }
    out.write_all(b"]}\n")?;
    Ok(())
}

pub(super) fn publish(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed =
        super::publish::settings::metadata_arguments(args, 5, 5, &[b"--update", b"--timeout"])?;
    let update = parsed.value(b"--update").map(OsStr::as_bytes);
    let timeout = parsed.value(b"--timeout");
    let args = parsed.positional;
    let key = KeyFile::open(Path::new(args[1]))?;
    let mut graph = Graph::open(
        Path::new(args[2]),
        key.public_key(),
        Limits::default(),
        store::Limits::default(),
    )?;
    let identifier = args[3].as_bytes();
    let uri = Uri::parse(args[4].as_bytes(), UriLimits::default())?;
    let source = EndpointSource::unix(Path::new(args[0]).to_path_buf());
    let options = UblockOptions::new(
        target(&source, duration(timeout.as_ref())?)?,
        parsed.publication.select(source.clock().as_ref())?,
    );
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut identity = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [ReservationSlot::default(); 1];
            let client = datastore_client(&mut identity, &mut slots, &mut reservations, source)?;
            Ok::<_, Box<dyn Error>>(
                Buffers::new()
                    .store_managed_namespace(
                        client,
                        &key,
                        &mut graph,
                        identifier,
                        update,
                        uri,
                        metadata.as_ref(),
                        options,
                        |_| Control::Continue,
                    )
                    .await,
            )
        })?;
    let published = sks(key.public_key(), identifier)?;
    match result {
        Ok(done) => {
            row(
                out,
                &json!({"event":"fs_namespace_published","uri":std::str::from_utf8(&published).ok(),"uri_bytes":published,
                "acknowledged_terms":done.publication.progress.accepted,"stored_bytes":done.publication.progress.wire_bytes,
                "graph_record":done.record.map(|id|id.index()),"graph_records_total":graph.record_count(),
                "connection_cleanup":done.publication.cleanup.as_ref().map(ToString::to_string)}),
            )?;
            Ok(())
        }
        Err(error) => {
            let accepted=error.accepted.as_ref().map(|accepted|json!({
                "acknowledged_terms":accepted.publication.progress.accepted,"stored_bytes":accepted.publication.progress.wire_bytes,
                "last_query":accepted.publication.progress.last_query.as_ref().map(|q|hex(q)),
                "connection_cleanup":accepted.publication.cleanup.as_ref().map(ToString::to_string),
                "graph_record_pending":true}));
            let _output = row(
                out,
                &json!({"event":"fs_namespace_publish_failed","uri_bytes":published,"accepted":accepted,
                "retirement_error":error.retirement_error.as_ref().map(ToString::to_string),"cause":error.cause.to_string(),"error":error.to_string()}),
            );
            Err(error)
        }
    }
}
