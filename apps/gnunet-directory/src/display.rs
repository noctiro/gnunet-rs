use crate::{
    Failure,
    run::{Facts, Guard},
};
use gnunet_fs::{
    directory,
    metadata::{self, Format},
};
use std::{
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

pub(super) async fn emit(
    out: &mut impl Write,
    bytes: &[u8],
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    let mut at = 0;
    while at < bytes.len() {
        guard.check().await?;
        let end = bytes.len().min(at.saturating_add(4096));
        match out.write(&bytes[at..end]) {
            Ok(0) => {
                guard.output_failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original directory stdout made no progress",
                )
                .into());
            }
            Ok(n) => {
                at += n;
                facts.stdout_bytes += n as u128;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                tokio::task::yield_now().await;
            }
            Err(e) => {
                guard.output_failed = true;
                return Err(e.into());
            }
        }
        guard.turn().await?;
    }
    Ok(())
}
/// Quoted printable Unicode when the exact source bytes are UTF8; otherwise
/// reversible ASCII byte escapes. No lossy replacement or terminal controls.
pub(super) async fn quoted(
    out: &mut impl Write,
    bytes: &[u8],
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    emit(out, b"\"", guard, facts).await?;
    let mut buffer = [0u8; 512];
    let mut used = 0;
    if let Ok(text) = std::str::from_utf8(bytes) {
        for ch in text.chars() {
            for escaped in ch.escape_debug() {
                let mut encoded = [0u8; 4];
                let word = escaped.encode_utf8(&mut encoded).as_bytes();
                if used + word.len() > buffer.len() {
                    emit(out, &buffer[..used], guard, facts).await?;
                    used = 0;
                }
                buffer[used..used + word.len()].copy_from_slice(word);
                used += word.len();
            }
        }
    } else {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in bytes {
            let mut escaped = [0u8; 4];
            let word = if (0x20..=0x7e).contains(&byte) && byte != b'\\' && byte != b'"' {
                escaped[0] = byte;
                &escaped[..1]
            } else {
                escaped = [
                    b'\\',
                    b'x',
                    HEX[usize::from(byte >> 4)],
                    HEX[usize::from(byte & 15)],
                ];
                &escaped[..]
            };
            if used + word.len() > buffer.len() {
                emit(out, &buffer[..used], guard, facts).await?;
                used = 0;
            }
            buffer[used..used + word.len()].copy_from_slice(word);
            used += word.len();
        }
    }
    emit(out, &buffer[..used], guard, facts).await?;
    emit(out, b"\"", guard, facts).await
}
fn terminated(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(&[0]).unwrap_or(bytes)
}
async fn optional(
    out: &mut impl Write,
    bytes: Option<&[u8]>,
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    match bytes {
        Some(b) => quoted(out, terminated(b), guard, facts).await,
        None => emit(out, b"none", guard, facts).await,
    }
}
async fn items(
    out: &mut impl Write,
    md: metadata::Metadata<'_>,
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    for item in md.items() {
        facts.metadata_items += 1;
        emit(
            out,
            format!("  type={} format={:?} plugin=", item.kind, item.format).as_bytes(),
            guard,
            facts,
        )
        .await?;
        optional(out, item.plugin, guard, facts).await?;
        emit(out, b" mime=", guard, facts).await?;
        optional(out, item.mime, guard, facts).await?;
        emit(out, b" value=", guard, facts).await?;
        if item.kind == 174 {
            emit(
                out,
                format!(
                    "<embedded original data: {} bytes; unverified>",
                    item.data.len()
                )
                .as_bytes(),
                guard,
                facts,
            )
            .await?;
        } else if item.format == Format::Binary {
            emit(
                out,
                format!("<binary: {} bytes>", item.data.len()).as_bytes(),
                guard,
                facts,
            )
            .await?;
        } else {
            // Remove only the required last terminator. Any internal NUL remains
            // an explicit escape rather than hiding original trailing bytes.
            quoted(out, terminated(item.data), guard, facts).await?;
        }
        emit(
            out,
            format!(" [data-bytes={}]\n", item.data.len()).as_bytes(),
            guard,
            facts,
        )
        .await?;
    }
    Ok(())
}
pub(super) async fn begin(
    out: &mut impl Write,
    path: &Path,
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    emit(out, b"Directory file ", guard, facts).await?;
    quoted(out, path.as_os_str().as_bytes(), guard, facts).await?;
    emit(
        out,
        b" (local syntax only; no source authentication):\n",
        guard,
        facts,
    )
    .await
}
pub(super) async fn event(
    out: &mut impl Write,
    event: directory::Event<'_>,
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    match event {
        directory::Event::Directory { metadata, .. } => {
            emit(out, b"Root metadata for ", guard, facts).await?;
            optional(out, directory::filename(metadata.items()), guard, facts).await?;
            emit(out, b":\n", guard, facts).await?;
            items(out, metadata, guard, facts).await?;
            emit(out, b"Contents:\n", guard, facts).await?;
        }
        directory::Event::Entry(entry) => {
            facts.entries += 1;
            emit(out, b"Entry ", guard, facts).await?;
            optional(
                out,
                directory::filename(entry.metadata.items()),
                guard,
                facts,
            )
            .await?;
            emit(out, b" uri=", guard, facts).await?;
            quoted(out, entry.raw_uri, guard, facts).await?;
            emit(out, b":\n", guard, facts).await?;
            items(out, entry.metadata, guard, facts).await?;
        }
        directory::Event::Padding { .. } => {}
    }
    Ok(())
}
pub(super) async fn complete(
    out: &mut impl Write,
    summary: directory::Summary,
    guard: &mut Guard,
    facts: &mut Facts,
) -> Result<(), Failure> {
    emit(
        out,
        format!(
            "Directory complete: entries={} extent={} (syntax only)\n\n",
            summary.entries, summary.end
        )
        .as_bytes(),
        guard,
        facts,
    )
    .await
}
