//! Shared actual GNUnet GNS-record and installed ABD command text formats. No plugin ABI, runtime,
//! allocation, crypto, key-file access or protocol-specific JSON representation.
#![no_std]
#![forbid(unsafe_code)]
pub use gnunet_dns::Idna;
pub use gnunet_gnsrecord::RecordType;
pub use gnunet_types::Error;
/// Explicit C layout of the original ABD ATTR record source.
pub use gnunet_wire::official::abd::RecordLayout as AbdLayout;
pub use gnunet_wire::official::messenger::profile::Profile;
use zeroize::Zeroize;
mod abd;
mod dns;
mod gns;
mod helpers;
mod messenger;
mod phone;
/// Allocation-free active NAMESTORE record-line grammar.
pub mod recordline;
mod registry;
/// Bounded allocation-free official zonefile text reader.
pub mod zonefile;
pub use registry::{is_critical, type_name, typename_to_number};
/// Finite input/output and nesting bounds. Scratch may impose smaller limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete text input or binary input inspected.
    pub input_bytes: usize,
    /// Maximum complete result produced, independent of caller output length.
    pub output_bytes: usize,
    /// Maximum BOX/SBOX wrapper nesting; traversal never uses recursion.
    pub depth: usize,
    /// Complete existing DNS reader's name/label/pointer work budget.
    pub dns_work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 262140,
            output_bytes: 262140,
            depth: 64,
            dns_work: 8388608,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.input_bytes == 0
            || self.output_bytes == 0
            || self.depth == 0
            || self.depth > 64
            || self.dns_work == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Exclusive zeroizing caller-owned staging, DNS name arena and text scratch.
/// No returned view borrows this storage. It is erased on initialization,
/// success, error and Drop; final caller output is committed only on success.
pub struct Workspace<'a> {
    stage: &'a mut [u8],
    names: &'a mut [u8],
    work: &'a mut [u8],
}
impl<'a> Workspace<'a> {
    /// Bind caller memory. DNS SOA needs up to510 name bytes; native Unicode
    /// projection may need1024 work bytes. Staging must hold the whole result.
    pub fn new(stage: &'a mut [u8], names: &'a mut [u8], work: &'a mut [u8]) -> Self {
        let mut this = Self { stage, names, work };
        this.clear();
        this
    }
    /// Erase complete original storage, including unused capacities.
    pub fn clear(&mut self) {
        self.stage.zeroize();
        self.names.zeroize();
        self.work.zeroize();
    }
}
impl Drop for Workspace<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
/// Reusable record text port with an explicit complete IDNA backend and native
/// Messenger producer profile. Neither backend nor Unicode data is copied here.
pub struct Codec<'a, I: Idna> {
    idna: &'a I,
    scratch: Workspace<'a>,
    profile: Profile,
    abd_layout: AbdLayout,
    limits: Limits,
}
impl<'a, I: Idna> Codec<'a, I> {
    /// Select existing DNS/IDNA semantics, packed producer layout and finite caps.
    pub fn new(
        idna: &'a I,
        scratch: Workspace<'a>,
        profile: Profile,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        profile.validate()?;
        Ok(Self {
            idna,
            scratch,
            profile,
            abd_layout: AbdLayout::native(),
            limits,
        })
    }
    /// Select the known original ABD ATTR C layout. No incoming record is
    /// guessed, and this selector changes no signed DEL bytes or other grammar.
    pub fn with_abd_layout(mut self, layout: AbdLayout) -> Result<Self, Error> {
        layout.validate()?;
        self.abd_layout = layout;
        Ok(self)
    }
    /// Convert actual plugin text to a complete official binary record value,
    /// without an added C terminator except where the record schema requires it.
    /// Unsupported types fail without changing caller output. ABD DEL/ATTR
    /// grammar is required by the installed command; its C plugin is not built.
    pub fn string_to_value(
        &mut self,
        kind: RecordType,
        text: &str,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.scratch.clear();
        let result = (|| {
            if text.len() > self.limits.input_bytes {
                return Err(Error::TooLarge);
            }
            if text.as_bytes().contains(&0) {
                return Err(Error::InvalidInput);
            }
            let cap = self
                .scratch
                .stage
                .len()
                .min(self.limits.output_bytes)
                .min(65535);
            let mut out = helpers::Writer::new(&mut self.scratch.stage[..cap]);
            let (kind, text) = gns::parse_boxes(kind, text, &mut out, self.limits.depth)?;
            if dns::supported(kind) {
                dns::parse(
                    kind,
                    text,
                    &mut out,
                    self.idna,
                    self.scratch.names,
                    self.scratch.work,
                )?;
            } else if kind == RecordType::PHONE {
                phone::parse(text, &mut out)?;
            } else if abd::supported(kind) {
                abd::parse(kind, text, &mut out, self.abd_layout)?;
            } else if messenger::supported(kind) {
                messenger::parse(kind, text, &mut out, self.profile)?;
            } else {
                gns::parse(kind, text, &mut out)?;
            }
            let n = out.len();
            if n > output.len() {
                return Err(Error::Capacity);
            }
            output[..n].copy_from_slice(&self.scratch.stage[..n]);
            Ok(n)
        })();
        self.scratch.clear();
        result
    }
    /// Convert binary record data to the actual active plugin's UTF-8 text,
    /// without a terminating NUL. This performs no record authorization, key
    /// derivation, signature/proof check or decryption. Errors preserve output.
    pub fn value_to_string(
        &mut self,
        kind: RecordType,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.scratch.clear();
        let result = (|| {
            if data.len() > self.limits.input_bytes || data.len() > 65535 {
                return Err(Error::TooLarge);
            }
            let cap = self.scratch.stage.len().min(self.limits.output_bytes);
            let mut out = helpers::Writer::new(&mut self.scratch.stage[..cap]);
            let (kind, data) = gns::format_boxes(kind, data, &mut out, self.limits.depth)?;
            if dns::supported(kind) {
                dns::format(
                    kind,
                    data,
                    &mut out,
                    self.idna,
                    self.scratch.names,
                    self.scratch.work,
                    self.limits.dns_work,
                )?;
            } else if kind == RecordType::PHONE {
                phone::format(data, &mut out)?;
            } else if abd::supported(kind) {
                abd::format(kind, data, &mut out, self.abd_layout)?;
            } else if messenger::supported(kind) {
                messenger::format(kind, data, &mut out, self.profile)?;
            } else {
                gns::format(kind, data, &mut out)?;
            }
            let n = out.len();
            core::str::from_utf8(&self.scratch.stage[..n]).map_err(|_| Error::Malformed)?;
            if n > output.len() {
                return Err(Error::Capacity);
            }
            output[..n].copy_from_slice(&self.scratch.stage[..n]);
            Ok(n)
        })();
        self.scratch.clear();
        result
    }
}

#[cfg(test)]
mod abd_tests;
