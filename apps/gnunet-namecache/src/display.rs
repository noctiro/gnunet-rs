//! Interpret only the signature-checked, zone/name-bound decrypted record set.
use crate::Cause;
use gnunet_gnscrypto::Label;
use gnunet_gnsrecord::ZoneKey;
use gnunet_gnsrecord_text::{Codec, Limits, Profile, Workspace};
use std::io::{self, Write};
use zeroize::Zeroizing;

/// An output refusal never upgrades a partial stdout write to a complete display.
pub(super) struct Output<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Output<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            remaining: 8 * 1024 * 1024,
        }
    }
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<W: Write> Write for Output<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > self.remaining {
            return Err(io::Error::other(
                "NAMECACHE display exceeds 8 MiB output policy",
            ));
        }
        let n = self.inner.write(input)?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
pub(super) fn bytes(size: usize) -> Result<Zeroizing<Vec<u8>>, Cause> {
    let mut output = Zeroizing::new(Vec::new());
    output.try_reserve_exact(size)?;
    output.resize(size, 0);
    Ok(output)
}
fn escaped(output: &mut impl Write, text: &str) -> io::Result<()> {
    for ch in text.chars() {
        if ch.is_control() {
            write!(output, "{}", ch.escape_default())?;
        } else {
            write!(output, "{ch}")?;
        }
    }
    Ok(())
}
fn hex(output: &mut impl Write, data: &[u8]) -> io::Result<()> {
    for byte in data {
        write!(output, "{byte:02x}")?;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Records {
    pub applicable: usize,
    pub unsupported_or_corrupt: usize,
    pub block_expiration: u64,
}
pub(super) fn records(
    output: &mut impl Write,
    original: &gnunet_namecache_client_host::Block,
    zone: ZoneKey,
    label: Label<'_>,
    now: u64,
    profile: Profile,
) -> Result<Records, Cause> {
    // Native client has already checked the carried-key signature/query and
    // inner/outer expiry agreement. This second boundary binds that key to the
    // actual public zone and normalized name before any plaintext is exposed.
    let block = gnunet_gnscrypto::Block::decode(original.bytes())?;
    let verified = block.verify_for(zone, label)?;
    let mut plaintext = bytes(gnunet_gnsrecord::MAX_BLOCK_SIZE)?;
    let opened = verified.open_at(now, &mut plaintext)?;
    let mut stage = bytes(262_140)?;
    let mut names = bytes(1024)?;
    let mut work = bytes(4096)?;
    let mut text = bytes(262_140)?;
    let mut idna_work = gnunet_idna::Workspace::new();
    let idna = gnunet_idna::Backend::new(
        &mut idna_work,
        gnunet_idna::Limits::GNUNET,
        gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut codec = Codec::new(
        &idna,
        Workspace::new(&mut stage, &mut names, &mut work),
        profile,
        Limits::default(),
    )?;
    escaped(output, label.as_str())?;
    writeln!(
        output,
        ": block-expiration-us={} verified-zone-name=true",
        block.expiration()?
    )?;
    let mut facts = Records {
        applicable: 0,
        unsupported_or_corrupt: 0,
        block_expiration: block.expiration()?,
    };
    for record in opened.iter() {
        let record = record?;
        facts.applicable += 1;
        write!(
            output,
            "\t{}({}) expiration-us={} flags=0x{:04x}: ",
            gnunet_gnsrecord_text::type_name(record.record_type).unwrap_or("UNKNOWN"),
            record.record_type.value(),
            record.expiration_time,
            record.flags.bits()
        )?;
        match codec.value_to_string(record.record_type, record.data, &mut text) {
            Ok(n) => escaped(output, std::str::from_utf8(&text[..n])?)?,
            Err(error) => {
                facts.unsupported_or_corrupt += 1;
                write!(output, "unsupported-or-corrupt({error}); raw-hex=")?;
                hex(output, record.data)?;
            }
        }
        writeln!(output)?;
    }
    if facts.applicable == 0 {
        writeln!(output, "\tNo applicable records found")?;
    }
    Ok(facts)
}
pub(super) fn missing(output: &mut impl Write, label: &str) -> io::Result<()> {
    write!(output, "No matching block found for `")?;
    escaped(output, label)?;
    writeln!(output, "'")
}
pub(super) fn deleted(output: &mut impl Write, label: &str, code: i32) -> io::Result<()> {
    match code {
        gnunet_namecache_client_host::ipc::OK => write!(output, "Removed cached block for `")?,
        gnunet_namecache_client_host::ipc::NO => write!(output, "No cached block for `")?,
        _ => write!(output, "Failed to remove cached block for `")?,
    }
    escaped(output, label)?;
    writeln!(output, "' (result={code})")
}
