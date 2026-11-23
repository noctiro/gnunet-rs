//! Local address-family assignments keyed by official peer identity.
use crate::AfProfile;
use gnunet_types::Error;

const MAX_PROFILES: usize = 64;

/// Bounded address-family assignments for authenticated peer identities.
/// The table is sorted by the decoded identity and allocates no heap storage.
pub struct PeerProfiles {
    fallback: Option<AfProfile>,
    peers: [([u8; 32], AfProfile); MAX_PROFILES],
    count: usize,
}

impl PeerProfiles {
    /// An empty assignment table with an explicit Linux gateway fallback.
    pub const LINUX: Self = Self::empty(Some(AfProfile::LINUX));
    /// An empty table with native named-service defaults and the Linux gateway profile.
    pub const NATIVE: Self = Self::empty(None);

    const fn empty(fallback: Option<AfProfile>) -> Self {
        Self {
            fallback,
            peers: [([0; 32], AfProfile::LINUX); MAX_PROFILES],
            count: 0,
        }
    }

    /// Validate a default profile and one assignment per decoded peer identity.
    pub fn new(
        fallback: AfProfile,
        assignments: impl IntoIterator<Item = ([u8; 32], AfProfile)>,
    ) -> Result<Self, Error> {
        fallback.validate()?;
        let mut table = Self::empty(Some(fallback));
        for (peer, profile) in assignments {
            table.insert(peer, profile)?;
        }
        Ok(table)
    }

    /// Build an assignment table from a semicolon-separated `PEER PROFILE` list.
    /// Recognized peer encodings are GNUnet base32 and hexadecimal. Duplicate
    /// decoded identities, unknown profile names and excess entries are errors.
    pub fn parse(fallback: AfProfile, list: &str) -> Result<Self, Error> {
        Self::parse_with_optional_fallback(Some(fallback), list)
    }

    /// Parse exact assignments and an optional explicit fallback for unassigned peers.
    pub fn parse_with_optional_fallback(
        fallback: Option<AfProfile>,
        list: &str,
    ) -> Result<Self, Error> {
        if let Some(profile) = fallback {
            profile.validate()?;
        }
        let mut table = Self::empty(fallback);
        for entry in list
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let mut fields = entry.split_ascii_whitespace();
            let (Some(peer), Some(profile), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(Error::InvalidInput);
            };
            table.insert(parse_peer_identity(peer)?, profile.parse()?)?;
        }
        Ok(table)
    }

    fn insert(&mut self, peer: [u8; 32], profile: AfProfile) -> Result<(), Error> {
        profile.validate()?;
        if self.count == MAX_PROFILES {
            return Err(Error::Capacity);
        }
        let position = match self.position(&peer) {
            Ok(_) => return Err(Error::Conflict),
            Err(position) => position,
        };
        self.peers.copy_within(position..self.count, position + 1);
        self.peers[position] = (peer, profile);
        self.count += 1;
        Ok(())
    }

    fn position(&self, peer: &[u8; 32]) -> Result<usize, usize> {
        self.peers[..self.count].binary_search_by(|entry| entry.0.cmp(peer))
    }

    /// Address-family profile of this verified peer when explicitly configured.
    #[must_use]
    pub fn assigned(&self, peer: &[u8; 32]) -> Option<AfProfile> {
        self.position(peer).ok().map(|index| self.peers[index].1)
    }

    /// Default codec for peers without an assignment.
    #[must_use]
    pub const fn fallback(&self) -> AfProfile {
        match self.fallback {
            Some(profile) => profile,
            None => AfProfile::native(),
        }
    }

    /// Explicit profile for the verified peer, or the configured fallback.
    #[must_use]
    pub fn profile(&self, peer: &[u8; 32]) -> AfProfile {
        self.assigned(peer).unwrap_or_else(|| self.fallback())
    }

    /// Select the transmit profile for a discovered Internet gateway.
    /// The official C build ships the gateway's required helper on Linux, so
    /// unassigned gateways default to that wire profile. This is a codec choice.
    #[must_use]
    pub fn gateway_profile(&self, peer: &[u8; 32]) -> AfProfile {
        self.assigned(peer)
            .or(self.fallback)
            .unwrap_or(AfProfile::LINUX)
    }
}

/// Decode a configured GNUnet peer identity from 52 base32 or 64 hex digits.
/// The textual identity grants no peer authentication.
pub fn parse_peer_identity(text: &str) -> Result<[u8; 32], Error> {
    let mut output = [0; 32];
    match text.len() {
        64 => {
            let hex = |byte: u8| {
                char::from(byte)
                    .to_digit(16)
                    .map(|digit| digit as u8)
                    .ok_or(Error::InvalidInput)
            };
            for (byte, digits) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
                *byte = hex(digits[0])? << 4 | hex(digits[1])?;
            }
        }
        52 => {
            let mut accumulator = 0u16;
            let mut bits = 0;
            let mut bytes = output.iter_mut();
            for byte in text.bytes() {
                let digit = match byte.to_ascii_uppercase() {
                    b'O' => b'0',
                    b'I' | b'L' => b'1',
                    b'U' => b'V',
                    digit => digit,
                };
                let digit = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
                    .iter()
                    .position(|byte| *byte == digit)
                    .ok_or(Error::InvalidInput)?;
                accumulator = ((accumulator & ((1 << bits) - 1)) << 5) | digit as u16;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    *bytes.next().ok_or(Error::InvalidInput)? = (accumulator >> bits) as u8;
                }
            }
        }
        _ => return Err(Error::InvalidInput),
    }
    Ok(output)
}
