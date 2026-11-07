use gnunet_namestore::RecordType;
/// Active pinned built-in record criticality: the GNS plugin marks these four
/// types, the DNS plugin returns false, and other active built-ins provide no
/// critical callback. No dynamic C plugin is loaded. Native embedders may inject
/// their actual extended registry predicate into Server::recover instead.
#[must_use]
pub fn critical_type(kind: RecordType) -> bool {
    matches!(
        kind,
        RecordType::PKEY | RecordType::EDKEY | RecordType::GNS2DNS | RecordType::REDIRECT
    )
}
