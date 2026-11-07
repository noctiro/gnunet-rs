//! Values from GNUnet v0.29.1's generated GANA record registry.

/// An official DNS/GNS record type, retaining unrecognized 32-bit codepoints.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordType(u32);

impl RecordType {
    /// Official GNS wildcard query type.
    pub const ANY: Self = Self(0);
    /// DNS IPv4 address.
    pub const A: Self = Self(1);
    /// DNS name-server delegation.
    pub const NS: Self = Self(2);
    /// DNS canonical-name alias.
    pub const CNAME: Self = Self(5);
    /// DNS start of authority.
    pub const SOA: Self = Self(6);
    /// DNS pointer record.
    pub const PTR: Self = Self(12);
    /// DNS mail exchange.
    pub const MX: Self = Self(15);
    /// DNS text data.
    pub const TXT: Self = Self(16);
    /// DNS IPv6 address.
    pub const AAAA: Self = Self(28);
    /// DNS service location.
    pub const SRV: Self = Self(33);
    /// DNS certificate record.
    pub const CERT: Self = Self(37);
    /// DNS DNAME alias.
    pub const DNAME: Self = Self(39);
    /// DNS TLS authentication association.
    pub const TLSA: Self = Self(52);
    /// DNS S/MIME authentication association.
    pub const SMIMEA: Self = Self(53);
    /// DNS URI resource record.
    pub const URI: Self = Self(256);
    /// DNS certificate authority authorization.
    pub const CAA: Self = Self(257);
    /// GNS ECDSA zone delegation.
    pub const PKEY: Self = Self(65536);
    /// GNS zone nickname.
    pub const NICK: Self = Self(65537);
    /// Legacy hostname.
    pub const LEHO: Self = Self(65538);
    /// VPN resolution.
    pub const VPN: Self = Self(65539);
    /// Delegation from GNS to DNS.
    pub const GNS2DNS: Self = Self(65540);
    /// A boxed protocol/service record.
    pub const BOX: Self = Self(65541);
    /// SecuShare social place.
    pub const PLACE: Self = Self(65542);
    /// Conversation endpoint.
    pub const PHONE: Self = Self(65543);
    /// re:claimID attribute.
    pub const RECLAIM_ATTRIBUTE: Self = Self(65544);
    /// Local re:claimID ticket reference.
    pub const RECLAIM_TICKET: Self = Self(65545);
    /// SBox record.
    pub const SBOX: Self = Self(65547);
    /// Attribute-based delegation policy.
    pub const DELEGATE: Self = Self(65548);
    /// Attribute-based delegation reverse lookup.
    pub const ATTRIBUTE: Self = Self(65549);
    /// re:claimID attribute reference.
    pub const RECLAIM_ATTRIBUTE_REF: Self = Self(65550);
    /// GNS redirection.
    pub const REDIRECT: Self = Self(65551);
    /// re:claimID OpenID Connect client name.
    pub const RECLAIM_OIDC_CLIENT: Self = Self(65552);
    /// re:claimID OpenID Connect redirect URI.
    pub const RECLAIM_OIDC_REDIRECT: Self = Self(65553);
    /// re:claimID attribute credential.
    pub const RECLAIM_CREDENTIAL: Self = Self(65554);
    /// re:claimID credential presentation.
    pub const RECLAIM_PRESENTATION: Self = Self(65555);
    /// GNS EdDSA zone delegation.
    pub const EDKEY: Self = Self(65556);
    /// ERIS binary read capability.
    pub const ERIS_READ_CAPABILITY: Self = Self(65557);
    /// Messenger room entry.
    pub const MESSENGER_ROOM_ENTRY: Self = Self(65558);
    /// Private tombstone for a deleted record.
    pub const TOMBSTONE: Self = Self(65559);
    /// Messenger room details.
    pub const MESSENGER_ROOM_DETAILS: Self = Self(65560);
    /// DID document.
    pub const DID_DOCUMENT: Self = Self(65561);
    /// Registered FAEST delegation codepoint; no FAEST codec is supplied here.
    pub const FAESTKEY: Self = Self(65562);
    /// Messenger room epoch key.
    pub const MESSENGER_ROOM_EPOCH_KEY: Self = Self(65563);
    /// Messenger encryption key.
    pub const MESSENGER_ENCRYPTION_KEY: Self = Self(65564);
    /// Private delegation registrar metadata.
    pub const GNS_REGISTRAR_METADATA: Self = Self(4294901760);

    /// Preserve a codepoint, including an extension not known to this release.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Numeric value used in the 32-bit network field.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Whether the current C implementation treats this as a zone delegation.
    #[must_use]
    pub const fn is_zone_delegation(self) -> bool {
        self.0 == Self::PKEY.0 || self.0 == Self::EDKEY.0
    }

    /// Fixed value size for A, AAAA, PKEY, and EDKEY; other schemas are variable.
    #[must_use]
    pub const fn fixed_size(self) -> Option<usize> {
        match self.0 {
            1 => Some(4),
            28 => Some(16),
            65536 | 65556 => Some(32),
            _ => None,
        }
    }
}

/// Official 16-bit GNS flags, retaining unknown bits for resolver policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RecordFlags(u16);

impl RecordFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// An unprocessable record with this bit requires resolution to fail.
    pub const CRITICAL: Self = Self(0x0001);
    /// Use only after the other applicable absolute records have expired.
    pub const SHADOW: Self = Self(0x0002);
    /// Supplemental record.
    pub const SUPPLEMENTAL: Self = Self(0x0004);
    /// Local maintenance record, including tombstones.
    pub const MAINTENANCE: Self = Self(0x2000);
    /// Expiration is a duration in microseconds rather than absolute UTC.
    pub const RELATIVE_EXPIRATION: Self = Self(0x4000);
    /// Local private record which must not be published.
    pub const PRIVATE: Self = Self(0x8000);
    /// All flag bits assigned in the pinned implementation.
    pub const KNOWN: Self = Self(0xe007);

    /// Preserve a raw bit mask without treating unknown bits as authorization.
    #[must_use]
    pub const fn from_bits_preserve(bits: u16) -> Self {
        Self(bits)
    }

    /// Flags in host byte order; serialization writes them in big endian.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every bit in `required` is present.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Combine masks without discarding unknown bits.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove the specified bits.
    #[must_use]
    pub const fn without(self, removed: Self) -> Self {
        Self(self.0 & !removed.0)
    }

    /// Unassigned bits which the owning protocol must handle according to policy.
    #[must_use]
    pub const fn unknown_bits(self) -> u16 {
        self.0 & !Self::KNOWN.0
    }
}
