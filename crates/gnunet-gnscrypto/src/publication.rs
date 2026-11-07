//! Publication-side record normalization with caller-selected UTC and plugins.
use crate::{Label, MAX_RECORDS};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_types::Error;

/// Public, absolute records ready for serialization and sealing. The record
/// values still borrow the caller's storage; no payload is copied or allocated.
pub struct Publication<'a, 'data> {
    records: &'a [RecordData<'data>],
    expiration: u64,
}
impl<'data> Publication<'_, 'data> {
    /// Filtered records, preserving original order and extension flags.
    #[must_use]
    pub const fn records(&self) -> &[RecordData<'data>] {
        self.records
    }
    /// Minimum of each record type's greatest lifetime, including shadows.
    /// The publication authority separately owns strict prior-block monotonicity.
    #[must_use]
    pub const fn expiration(&self) -> u64 {
        self.expiration
    }
}

/// Prepare the public subset using the official GNS record-set constraints:
/// omit private/expired/maintenance records, omit NICK at `@`, check delegation
/// and redirection exclusivity, and mark plugin-defined critical types. Relative
/// durations become saturating absolute microseconds before encryption.
/// Supplemental records, same-type inactive delegation/REDIRECT shadows and
/// GNS2DNS security material follow the shared authoritative set policy.
/// The result is the record-derived expiry only; a publishing authority still
/// must durably reserve strict prior-block monotonicity before sealing.
///
/// `is_critical` is the record owner's registry/plugin policy, corresponding to
/// `GNUNET_GNSRECORD_is_critical`; no private type registry is invented here.
/// Invalid sets and capacity refusal leave the output unchanged. `now` must be
/// supplied by a host with an adequate trusted UTC source.
pub fn prepare_publication_at<'a, 'data>(
    label: Label<'_>,
    records: &[RecordData<'data>],
    now: u64,
    is_critical: impl Fn(RecordType) -> bool,
    output: &'a mut [RecordData<'data>],
) -> Result<Publication<'a, 'data>, Error> {
    if records.len() > MAX_RECORDS {
        return Err(Error::TooLarge);
    }
    let mut count = 0_usize;
    gnunet_gnsrecord::validate_authoritative_records(label.as_str().as_bytes(), records, |r| {
        include(label, r, now)
    })?;
    for record in records.iter().filter(|record| include(label, record, now)) {
        record.encoded_len()?;
        count += 1;
    }
    if output.len() < count {
        return Err(Error::Capacity);
    }
    for (index, record) in records
        .iter()
        .filter(|record| include(label, record, now))
        .enumerate()
    {
        output[index] = *record;
        if record.has_relative_expiration() {
            output[index].expiration_time = now.saturating_add(record.expiration_time);
            output[index].flags = record.flags.without(RecordFlags::RELATIVE_EXPIRATION);
        }
        if is_critical(record.record_type) {
            output[index].flags = output[index].flags.union(RecordFlags::CRITICAL);
        }
    }
    let public = &output[..count];
    let mut expiration = if public.is_empty() { 0 } else { u64::MAX };
    // Caller-owned order is retained. This allocation-free helper has the same
    // explicit MAX_RECORDS bound as before; sorted scratch normalization in
    // NAMESTORE is used by the ordinary ZONEMASTER path.
    for record in public {
        let mut lifetime = record.expiration_time;
        for same_type in public {
            if same_type.record_type == record.record_type {
                lifetime = lifetime.max(same_type.expiration_time);
            }
        }
        expiration = expiration.min(lifetime);
    }
    Ok(Publication {
        records: public,
        expiration,
    })
}
fn include(label: Label<'_>, record: &RecordData<'_>, now: u64) -> bool {
    record.flags.bits() & (RecordFlags::PRIVATE.bits() | RecordFlags::MAINTENANCE.bits()) == 0
        && (record.has_relative_expiration() || record.expiration_time >= now)
        && !(label.as_str() == "@" && record.record_type == RecordType::NICK)
}
