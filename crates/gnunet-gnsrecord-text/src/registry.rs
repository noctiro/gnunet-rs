use crate::RecordType;
const TYPES: &[(RecordType, &str)] = &[
    (RecordType::ANY, "ANY"),
    (RecordType::A, "A"),
    (RecordType::NS, "NS"),
    (RecordType::CNAME, "CNAME"),
    (RecordType::SOA, "SOA"),
    (RecordType::PTR, "PTR"),
    (RecordType::MX, "MX"),
    (RecordType::TXT, "TXT"),
    (RecordType::AAAA, "AAAA"),
    (RecordType::SRV, "SRV"),
    (RecordType::CERT, "CERT"),
    (RecordType::TLSA, "TLSA"),
    (RecordType::SMIMEA, "SMIMEA"),
    (RecordType::URI, "URI"),
    (RecordType::CAA, "CAA"),
    (RecordType::PKEY, "PKEY"),
    (RecordType::EDKEY, "EDKEY"),
    (RecordType::DELEGATE, "DEL"),
    (RecordType::ATTRIBUTE, "ATTR"),
    (RecordType::PHONE, "PHONE"),
    (RecordType::NICK, "NICK"),
    (RecordType::LEHO, "LEHO"),
    (RecordType::VPN, "VPN"),
    (RecordType::GNS2DNS, "GNS2DNS"),
    (RecordType::BOX, "BOX"),
    (RecordType::SBOX, "SBOX"),
    (RecordType::REDIRECT, "REDIRECT"),
    (RecordType::TOMBSTONE, "✞"),
    (RecordType::RECLAIM_ATTRIBUTE, "RECLAIM_ATTRIBUTE"),
    (RecordType::RECLAIM_ATTRIBUTE_REF, "RECLAIM_ATTRIBUTE_REF"),
    (RecordType::RECLAIM_CREDENTIAL, "RECLAIM_CREDENTIAL"),
    (RecordType::RECLAIM_PRESENTATION, "RECLAIM_PRESENTATION"),
    (RecordType::RECLAIM_OIDC_CLIENT, "RECLAIM_OIDC_CLIENT"),
    (RecordType::RECLAIM_OIDC_REDIRECT, "RECLAIM_OIDC_REDIRECT"),
    (RecordType::RECLAIM_TICKET, "RECLAIM_TICKET"),
    (RecordType::MESSENGER_ROOM_ENTRY, "MESSENGER_ROOM_ENTRY"),
    (RecordType::MESSENGER_ROOM_DETAILS, "MESSENGER_ROOM_DETAILS"),
    (
        RecordType::MESSENGER_ROOM_EPOCH_KEY,
        "MESSENGER_ROOM_EPOCH_KEY",
    ),
    (
        RecordType::MESSENGER_ENCRYPTION_KEY,
        "MESSENGER_ENCRYPTION_KEY",
    ),
];
/// Canonical name from selected production grammars and the official ANY
/// special case. DEL/ATTR also serve the installed ABD command; its text plugin
/// itself is not built by active C Meson. PHONE is the selected conditional
/// Conversation plugin grammar. Other unsupported types return None.
pub fn type_name(kind: RecordType) -> Option<&'static str> {
    TYPES.iter().find(|(t, _)| *t == kind).map(|(_, n)| *n)
}
/// Case-insensitive actual active names. Numeric strings and invented aliases
/// are not plugin names; callers may handle explicit numeric types separately.
pub fn typename_to_number(name: &str) -> Option<RecordType> {
    TYPES
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(name))
        .map(|(t, _)| *t)
}
/// Active plugins' critical-type property, independent of each record's flags.
pub const fn is_critical(kind: RecordType) -> bool {
    matches!(
        kind,
        RecordType::PKEY | RecordType::EDKEY | RecordType::GNS2DNS | RecordType::REDIRECT
    )
}
