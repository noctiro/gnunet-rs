//! Shared authoritative record-set constraints from LSD0001/RFC9498.
use crate::{RecordData, RecordFlags, RecordType};
use gnunet_types::Error;

/// DNS records supported as connection-security material alongside GNS2DNS.
/// The resolver uses this same classification when retaining bridge security
/// inputs. Other extensions may be carried explicitly as supplemental records.
#[must_use]
pub const fn is_gns2dns_security_type(kind: RecordType) -> bool {
    matches!(
        kind.value(),
        37 | 43 | 44 | 46 | 48 | 52 | 53 | 59 | 60 | 63 | 64 | 65
    )
}

#[derive(Clone, Copy)]
enum Class {
    Empty,
    Zone(RecordType),
    Redirect,
    Dns,
    Security,
    Other,
}

/// Validate the authoritative combinations retained by an owner at one source
/// time. `retain` selects that owner's visible records; private filtering is a
/// separate caller decision. No value bytes are copied, parsed or formatted.
///
/// Supplemental records do not compete with the primary set. At most one
/// non-shadow delegation or REDIRECT is allowed, with same-type inactive
/// shadows. GNS2DNS can accompany supported DNS connection-security records.
/// Delegation/redirection types remain forbidden at the apex even when marked
/// supplemental. Maintenance and apex nickname metadata do not participate.
/// This is type/flag policy, not a signature, record-schema or trust check.
pub fn validate_authoritative_records<'a>(
    label: &[u8],
    records: &[RecordData<'a>],
    mut retain: impl FnMut(&RecordData<'a>) -> bool,
) -> Result<(), Error> {
    let apex = label == b"@";
    let mut class = Class::Empty;
    let mut active_unique = false;
    for record in records {
        if !retain(record)
            || record.flags.contains(RecordFlags::MAINTENANCE)
            || (apex && record.record_type == RecordType::NICK)
        {
            continue;
        }
        let kind = record.record_type;
        let unique = kind.is_zone_delegation() || kind == RecordType::REDIRECT;
        if apex && (unique || kind == RecordType::GNS2DNS) {
            return Err(Error::InvalidInput);
        }
        if record.flags.contains(RecordFlags::SUPPLEMENTAL) {
            continue;
        }
        let next = if kind.is_zone_delegation() {
            Class::Zone(kind)
        } else if kind == RecordType::REDIRECT {
            Class::Redirect
        } else if kind == RecordType::GNS2DNS {
            Class::Dns
        } else if is_gns2dns_security_type(kind) {
            Class::Security
        } else {
            Class::Other
        };
        class = match (class, next) {
            (Class::Empty, next) => next,
            (Class::Zone(old), Class::Zone(new)) if old == new => Class::Zone(old),
            (Class::Redirect, Class::Redirect) => Class::Redirect,
            (Class::Dns | Class::Security, Class::Dns) | (Class::Dns, Class::Security) => {
                Class::Dns
            }
            (Class::Security, Class::Security) => Class::Security,
            (Class::Other | Class::Security, Class::Other) | (Class::Other, Class::Security) => {
                Class::Other
            }
            _ => return Err(Error::InvalidInput),
        };
        if unique && !record.flags.contains(RecordFlags::SHADOW) {
            if active_unique {
                return Err(Error::InvalidInput);
            }
            active_unique = true;
        }
    }
    Ok(())
}
