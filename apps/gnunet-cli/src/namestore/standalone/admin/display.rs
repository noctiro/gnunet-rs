//! Native NAMESTORE text and round-trip-safe record-line displays.
use super::{Buffers, Display, RecordData, RecordFlags, RecordType, Result, ipc, storage};
use gnunet::{
    gnsrecord_text::{recordline, type_name},
    types::AbsoluteTime,
};
use gnunet_program_host::diagnostics;
use std::io::Write;
use zeroize::Zeroizing;

const OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINE: usize = 262140 + 512;

pub(super) struct Writer<'a, 'spec, W> {
    out: &'a mut W,
    spec: &'spec Display,
    codec: Buffers,
    line: Zeroizing<Vec<u8>>,
    remaining: usize,
}

impl<'a, 'spec, W: Write> Writer<'a, 'spec, W> {
    pub(super) fn new(out: &'a mut W, spec: &'spec Display) -> Result<Self> {
        Ok(Self {
            out,
            spec,
            codec: Buffers::new()?,
            line: storage(if spec.recordline { MAX_LINE } else { 0 })?,
            remaining: OUTPUT_BYTES,
        })
    }

    pub(super) fn records(
        &mut self,
        owner: &[u8],
        label: &[u8],
        records: ipc::Records<'_>,
    ) -> Result<()> {
        let mut header = false;
        for record in records.records().iter() {
            let record = record?;
            if (label != b"@" && record.record_type == RecordType::NICK)
                || self
                    .spec
                    .kind
                    .is_some_and(|kind| kind != record.record_type)
            {
                continue;
            }
            if !header {
                if self.spec.recordline {
                    let n = recordline::format_header(
                        std::str::from_utf8(label)?,
                        std::str::from_utf8(owner)?,
                        &mut self.line,
                    )?;
                    write(self.out, &mut self.remaining, &[&self.line[..n]])?;
                } else {
                    write(self.out, &mut self.remaining, &[label, b".", owner, b":\n"])?;
                }
                header = true;
            }
            self.record(record)?;
        }
        if header {
            self.out.flush()?;
        }
        Ok(())
    }

    fn record(&mut self, record: RecordData<'_>) -> Result<()> {
        if self.spec.recordline {
            let value = self.codec.recordline_value(record)?;
            let n = recordline::format_record(
                record.record_type,
                record.expiration_time,
                record.flags,
                value,
                &mut self.line,
            )?;
            return write(self.out, &mut self.remaining, &[&self.line[..n]]);
        }
        let value = self.codec.display_value(record);
        let (Some(kind), Ok(value)) = (type_name(record.record_type), value) else {
            let kind = record.record_type.value().to_string();
            return write(
                self.out,
                &mut self.remaining,
                &[
                    b"\tCorrupt or unsupported record of type ",
                    kind.as_bytes(),
                    b"\n",
                ],
            );
        };
        let expires = if record.flags.contains(RecordFlags::RELATIVE_EXPIRATION) {
            diagnostics::relative_time(record.expiration_time, true)
        } else {
            diagnostics::absolute_time(AbsoluteTime::from_micros(record.expiration_time))?
        };
        let visibility = if record.flags.contains(RecordFlags::PRIVATE) {
            b"PRIVATE".as_slice()
        } else {
            b"PUBLIC"
        };
        let shadow = if record.flags.contains(RecordFlags::SHADOW) {
            b"SHADOW".as_slice()
        } else {
            b""
        };
        let maintenance = if record.flags.contains(RecordFlags::MAINTENANCE) {
            b"MAINTENANCE".as_slice()
        } else {
            b""
        };
        write(
            self.out,
            &mut self.remaining,
            &[
                b"\t",
                kind.as_bytes(),
                b": ",
                value.as_bytes(),
                b" (",
                &expires,
                b")\t",
                visibility,
                b"\t",
                shadow,
                b"\t",
                maintenance,
                b"\n",
            ],
        )
    }

    pub(super) fn synchronized(&mut self) -> Result<()> {
        write(
            self.out,
            &mut self.remaining,
            &[b"Monitor is now in sync.\n"],
        )?;
        self.out.flush()?;
        Ok(())
    }

    pub(super) fn replenish(&mut self) {
        self.remaining = OUTPUT_BYTES;
    }
}

fn write(out: &mut impl Write, remaining: &mut usize, parts: &[&[u8]]) -> Result<()> {
    let length = parts.iter().try_fold(0usize, |length, part| {
        length
            .checked_add(part.len())
            .ok_or("NAMESTORE display length overflow")
    })?;
    *remaining = remaining
        .checked_sub(length)
        .ok_or("NAMESTORE output byte bound exceeded")?;
    for part in parts {
        out.write_all(part)?;
    }
    Ok(())
}
