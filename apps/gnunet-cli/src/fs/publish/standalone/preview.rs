//! Official text output over the bounded offline FS extraction worker.
use super::{Result, RootKeywords};
use gnunet::{
    fs::{directory, metadata as md},
    fs_host::extraction::{ExtractedObject, MetadataSettings, Policy, metadata_type_name},
    types::AbsoluteTime,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Instant,
};

pub(super) fn run(
    source: PathBuf,
    hard: Instant,
    metadata: MetadataSettings,
    creation_time: Option<AbsoluteTime>,
    root_keywords: &RootKeywords,
    verbose: u32,
    out: &mut crate::fs::Output<'_, impl Write>,
) -> Result<()> {
    let no_explicit = RootKeywords::default();
    let publication_date = creation_time
        .map(gnunet_program_host::diagnostics::absolute_time)
        .transpose()?;
    crate::fs::extract::inspect(
        source,
        hard,
        metadata,
        Policy::default(),
        out,
        |out, _, object| {
            let explicit = if object.relative.as_os_str().is_empty() {
                root_keywords
            } else {
                &no_explicit
            };
            row(out, object, explicit)
        },
        crate::fs::extract::Display::Official {
            verbose,
            publication_date,
        },
    )
}

fn row(out: &mut dyn Write, object: &ExtractedObject, explicit: &RootKeywords) -> io::Result<()> {
    let md::Decoded::Present(metadata) =
        md::decode_uncompressed(&object.metadata, md::Limits::default(), md::Mode::Strict)
            .map_err(io::Error::other)?
    else {
        return Err(io::Error::other("extracted metadata is a null marker"));
    };
    let filename = directory::filename(metadata.items()).unwrap_or(b"(null)");
    let (size, unit) = display_size(object.source_bytes);
    out.write_all(b"Meta data for file `")?;
    out.write_all(filename)?;
    writeln!(out, "' ({size} {unit})")?;
    for item in metadata.items().filter(|item| item.kind != 180) {
        if let Some(value) = item.text() {
            if let Some(name) = metadata_type_name(item.kind) {
                write!(out, "\t{name} - ")?;
            } else {
                write!(out, "\t{} - ", item.kind)?;
            }
            out.write_all(value)?;
            out.write_all(b"\n")?;
        }
    }
    out.write_all(b"Keywords for file `")?;
    out.write_all(filename)?;
    writeln!(out, "' ({size} {unit})")?;
    let terms = explicit
        .with_automatic(&object.keywords)
        .map_err(io::Error::other)?;
    let mut text = Vec::new();
    for term in terms {
        text.clear();
        text.extend(term.bytes());
        out.write_all(b"\t")?;
        out.write_all(&text)?;
        out.write_all(b"\n")?;
    }
    out.write_all(b"\n")?;
    out.flush()
}

fn display_size(mut size: u64) -> (u64, &'static str) {
    let mut unit = "b";
    for next in ["KiB", "MiB", "GiB", "TiB"] {
        if size <= 5 * 1024 {
            break;
        }
        size /= 1024;
        unit = next;
    }
    (size, unit)
}
