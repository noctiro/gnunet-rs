//! Explicit local resource/work policy; none of these values is a private wire field.
use crate::ContentLimits;
use gnunet_types::Error;
/// Whole-service bounds and per-original-operation work/storage ceilings.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous original local clients, including sets and listeners.
    pub clients: usize,
    /// Simultaneous unaccepted or adoption-pending original peer offers.
    pub incoming: usize,
    /// Simultaneous original committed peer operations across all set clients.
    pub operations: usize,
    /// Simultaneous one-use lazy-copy cookies tied to live original source sets.
    pub copies: usize,
    /// Simultaneous original immutable/retirement effects, including admitted debt.
    pub effects: usize,
    /// Conservative total retained immutable effect allocation charge.
    pub effect_bytes: usize,
    /// Service-wide body allocations (once per actual shared Body), view and
    /// algorithm capacities, immutable output and future intersection reserves.
    /// This is an admission bound, not a measured process/allocator footprint.
    pub retained_bytes: usize,
    /// Bounds for each local set and its original frozen membership.
    pub content: ContentLimits,
    /// Maximum unique original plus received elements in a union result.
    pub union_elements: usize,
    /// Maximum sum of payload capacities in one logical accumulated union.
    pub union_bytes: usize,
    /// Maximum nested application context before actual CADET frame admission.
    /// An oversized legal IPC context still fails if the original peer request
    /// cannot fit the actual public CADET application message; it is never truncated.
    pub context_bytes: usize,
    /// Original offer/operation lifetime in canonical microseconds, never renewed.
    pub operation_lifetime: u64,
    /// Maximum whole old13-byte-layout IBF bucket count, bounded by C sender2^20.
    pub ibf_buckets: usize,
    /// Maximum actual assembled Bloom-filter bytes per original intersection.
    pub bloom_bytes: usize,
    /// Maximum per-member Bloom hash work from untrusted peer metadata.
    /// Default64 covers ordinary C count-derived values (at most34).
    pub bloom_hashes: u32,
    /// Maximum actual filter/IBF reduction rounds per original operation.
    pub rounds: u16,
    /// Retained algorithm peer frames per original operation, before host transfer.
    pub output_frames: usize,
    /// Retained algorithm peer-frame bytes per original operation.
    pub output_bytes: usize,
    /// Maximum actual received peer records, including duplicate/repeated input.
    pub received_records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 64,
            incoming: 64,
            operations: 128,
            copies: 64,
            effects: 1024,
            effect_bytes: 16 * 1024 * 1024,
            retained_bytes: 64 * 1024 * 1024,
            content: ContentLimits::default(),
            union_elements: 16384,
            union_bytes: 16 * 1024 * 1024,
            context_bytes: 64512,
            operation_lifetime: 300_000_000,
            ibf_buckets: 1 << 20,
            bloom_bytes: 8 * 1024 * 1024,
            bloom_hashes: 64,
            rounds: 64,
            output_frames: 16,
            output_bytes: 256 * 1024,
            received_records: 65536,
        }
    }
}
impl Limits {
    /// Validate a finite explicit profile before reserving objects or starting IO.
    /// Zero peer/copy slots is an explicit local-only resource profile; it is
    /// never presented as the ordinary full-service default.
    pub fn validate(self) -> Result<(), Error> {
        self.content.validate()?;
        if self.clients == 0
            || self.clients > 65536
            || self.incoming > 65536
            || self.operations > 65536
            || self.copies > 65536
            || self.effects == 0
            || self.effects > 1_048_576
            || self.effect_bytes < 33312
            || self.retained_bytes < self.effect_bytes
            || self.union_elements < self.content.elements
            || u32::try_from(self.union_elements).is_err()
            || self.union_bytes < self.content.body_bytes
            || self.context_bytes > 64512
            || self.operation_lifetime == 0
            || self.operation_lifetime == u64::MAX
            || self.ibf_buckets < 4
            || self.ibf_buckets > 1_048_576
            || !self.ibf_buckets.is_power_of_two()
            || self.bloom_bytes < 8
            || self.bloom_hashes == 0
            || self.bloom_hashes > 4096
            || self.rounds == 0
            || self.output_frames == 0
            || self.output_bytes < 33312
            || self.output_bytes > self.effect_bytes
            || self.received_records == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
