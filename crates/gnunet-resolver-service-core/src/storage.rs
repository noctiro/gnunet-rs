//! Explicit profile and caller scratch shared by borrowed resolver storage.
use gnunet_types::Error;
/// Per-object/resource policy; aggregate bytes and metadata counts come from
/// caller slices, independently of the maximum legal individual DNS RDATA width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Native C-string byte maximum, independently of DNS wire-name width.
    pub max_name_bytes: usize,
    /// Maximum one RDATA blob (65535 supports the entire DNS width).
    pub max_record_bytes: usize,
    /// Explicit Rust CNAME work bound, not an upstream compression constant.
    pub cname_hops: usize,
}
impl Limits {
    /// Validate DNS widths without allocating or selecting any IDNA backend.
    pub fn validate(self) -> Result<Self, Error> {
        if self.max_name_bytes > 65535 || self.max_record_bytes > 65535 {
            return Err(Error::TooLarge);
        }
        Ok(self)
    }
}
/// Caller-owned native text conversion work. Neither field is retained by core.
/// Host can allocate these with Vec reserve/resize; no_std can use static slices.
pub struct TextScratch<'a> {
    /// Complete native decoded text or expansion output.
    pub native: &'a mut [u8],
    /// Independent IDNA intermediate text.
    pub work: &'a mut [u8],
    /// Name encoder arena, normally255 bytes, independent from RDATA storage.
    pub wire_name: &'a mut [u8],
}
