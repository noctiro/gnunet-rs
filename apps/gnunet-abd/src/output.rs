use crate::{Failure, run::Control};
use std::io::{self, Write};
use zeroize::Zeroizing;

/// Finite actual stdout bytes. No source-supplied byte is treated as terminal
/// control syntax by `escaped`; DEL records use the shared canonical formatter.
pub(super) struct Buffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Buffer {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            limit,
        }
    }
    pub fn append(&mut self, value: &[u8]) -> Result<(), Failure> {
        let n = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(gnunet_types::Error::Overflow)?;
        if n > self.limit {
            return Err("ABD output exceeds the configured byte bound".into());
        }
        if n > self.bytes.capacity() {
            let proposed = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(64)
                .max(n)
                .min(self.limit);
            let additional = proposed - self.bytes.len();
            if self.bytes.try_reserve_exact(additional).is_err() {
                self.bytes.try_reserve_exact(value.len())?;
            }
        }
        if self.bytes.capacity() > self.limit {
            return Err("ABD output allocation exceeds the configured byte bound".into());
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub fn number(&mut self, n: u32) -> Result<(), Failure> {
        self.append(n.to_string().as_bytes())
    }
    pub fn key(&mut self, key: gnunet_abd_client_host::ipc::Key<'_>) -> Result<(), Failure> {
        let zone = gnunet_gnsrecord::ZoneKey::from_wire(key.bytes())?;
        let mut encoded = [0u8; 64];
        self.append(zone.write_ztld(&mut encoded)?.as_bytes())
    }
    pub fn escaped(&mut self, input: &[u8]) -> Result<(), Failure> {
        self.append(b"\"")?;
        for byte in input {
            match *byte {
                b' '..=b'~' if *byte != b'"' && *byte != b'\\' => self.append(&[*byte])?,
                b'"' => self.append(b"\\\"")?,
                b'\\' => self.append(b"\\\\")?,
                other => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.append(&[
                        b'\\',
                        b'x',
                        HEX[usize::from(other >> 4)],
                        HEX[usize::from(other & 15)],
                    ])?;
                }
            }
        }
        self.append(b"\"")
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) async fn write(control: &mut Control, bytes: &[u8]) -> Result<(), Failure> {
    let previous = control.facts.borrow().output_bytes;
    if previous
        .checked_add(bytes.len())
        .ok_or(gnunet_types::Error::Overflow)?
        > control.settings.output_bytes
    {
        return Err("ABD output exceeds the configured byte bound".into());
    }
    // stdout is acquired only after the real terminal action/credential exists.
    // Synchronous OS writes and flush cannot be preempted; the same original
    // native/canonical deadline is checked before and after each bounded call.
    let stdout = io::stdout();
    let mut cursor = 0;
    while cursor < bytes.len() {
        control.gate().await?;
        let end = cursor.saturating_add(16384).min(bytes.len());
        let written = {
            let mut output = stdout.lock();
            output.write(&bytes[cursor..end])
        };
        match written {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ABD stdout made no progress",
                )
                .into());
            }
            Ok(n) => {
                cursor += n;
                control.facts.borrow_mut().output_bytes += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    control.gate().await?;
    stdout.lock().flush()?;
    control.facts.borrow_mut().output_flushed = true;
    control.gate().await
}

/// Canonical DEL has no escape grammar. Refuse terminal-control/newline bytes
/// instead of rewriting a signed role or injecting an extra output record.
pub(super) fn record_line(input: &[u8]) -> Result<(), Failure> {
    if std::str::from_utf8(input)?
        .chars()
        .any(|c| c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
    {
        return Err("canonical DEL text contains unrepresentable output control bytes".into());
    }
    Ok(())
}
