//! Official DNS class/opcode/return values and lossless network-value flags.
use crate::{Counts, Error, HEADER_LEN};

/// The twelve-octet DNS header, independent of any counted packet payload.
/// Decoding preserves all fields and does not validate or authenticate a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Original two transaction-ID octets, without native-endian conversion.
    pub id: [u8; 2],
    /// Lossless DNS flag word; header indications are untrusted.
    pub flags: Flags,
    /// Original four section counts, even when the payload is absent or malformed.
    pub counts: Counts,
}
impl Header {
    /// Read the complete fixed header without inspecting any trailing payload.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let bytes = input.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        let number = |i| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        Ok(Self {
            id: [bytes[0], bytes[1]],
            flags: Flags::from_bits_preserve(number(2)),
            counts: Counts {
                queries: number(4),
                answers: number(6),
                authority: number(8),
                additional: number(10),
            },
        })
    }
    /// Write exactly twelve octets; insufficient capacity changes no output byte.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let output = output.get_mut(..HEADER_LEN).ok_or(Error::Capacity)?;
        output[..2].copy_from_slice(&self.id);
        for (chunk, value) in output[2..].as_chunks_mut::<2>().0.iter_mut().zip([
            self.flags.bits(),
            self.counts.queries,
            self.counts.answers,
            self.counts.authority,
            self.counts.additional,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        Ok(HEADER_LEN)
    }
}
/// Official GNUnet DNS traffic classes; unknown class numbers remain representable.
pub mod class {
    /// Native public assignment INTERNET=1.
    pub const INTERNET: u16 = 1;
    /// Native public assignment CHAOS=3.
    pub const CHAOS: u16 = 3;
    /// Native public assignment HESIOD=4.
    pub const HESIOD: u16 = 4;
}
/// Official named DNS opcodes; all four-bit values remain representable.
pub mod opcode {
    /// Native public assignment QUERY=0.
    pub const QUERY: u8 = 0;
    /// Native public assignment INVERSE_QUERY=1.
    pub const INVERSE_QUERY: u8 = 1;
    /// Native public assignment STATUS=2.
    pub const STATUS: u8 = 2;
}
/// Official named DNS return codes; all four-bit values remain representable.
pub mod return_code {
    /// Native public assignment NO_ERROR=0.
    pub const NO_ERROR: u8 = 0;
    /// Native public assignment FORMAT_ERROR=1.
    pub const FORMAT_ERROR: u8 = 1;
    /// Native public assignment SERVER_FAILURE=2.
    pub const SERVER_FAILURE: u8 = 2;
    /// Native public assignment NAME_ERROR=3.
    pub const NAME_ERROR: u8 = 3;
    /// Native public assignment NOT_IMPLEMENTED=4.
    pub const NOT_IMPLEMENTED: u8 = 4;
    /// Native public assignment REFUSED=5.
    pub const REFUSED: u8 = 5;
    /// Native public assignment YXDOMAIN=6.
    pub const YXDOMAIN: u8 = 6;
    /// Native public assignment YXRRSET=7.
    pub const YXRRSET: u8 = 7;
    /// Native public assignment NXRRSET=8.
    pub const NXRRSET: u8 = 8;
    /// Native public assignment NOT_AUTH=9.
    pub const NOT_AUTH: u8 = 9;
    /// Native public assignment NOT_ZONE=10.
    pub const NOT_ZONE: u8 = 10;
}
/// Lossless DNS flags as the network-order numerical value in Packet.flags.
/// Header indications are untrusted data. In particular, AD does not establish
/// cryptographic verification. This type never changes bits while parsing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flags(u16);
impl Flags {
    /// Preserve every wire bit, including the reserved zero bit.
    pub const fn from_bits_preserve(bits: u16) -> Self {
        Self(bits)
    }
    /// Entire network-value flag word, suitable for Packet.flags.
    pub const fn bits(self) -> u16 {
        self.0
    }
    const fn flag(self, mask: u16) -> bool {
        self.0 & mask != 0
    }
    const fn with_flag(self, mask: u16, value: bool) -> Self {
        Self((self.0 & !mask) | if value { mask } else { 0 })
    }
    /// RD: the query requests recursion.
    pub const fn recursion_desired(self) -> bool {
        self.flag(0x100)
    }
    /// Replace only the recursion_desired indication, preserving all other bits.
    pub const fn with_recursion_desired(self, value: bool) -> Self {
        self.with_flag(0x100, value)
    }
    /// TC: the sender reports truncation.
    pub const fn message_truncated(self) -> bool {
        self.flag(0x200)
    }
    /// Replace only the message_truncated indication, preserving all other bits.
    pub const fn with_message_truncated(self, value: bool) -> Self {
        self.with_flag(0x200, value)
    }
    /// AA: the sender reports an authoritative answer.
    pub const fn authoritative_answer(self) -> bool {
        self.flag(0x400)
    }
    /// Replace only the authoritative_answer indication, preserving all other bits.
    pub const fn with_authoritative_answer(self, value: bool) -> Self {
        self.with_flag(0x400, value)
    }
    /// QR: true for response, false for query.
    pub const fn query_or_response(self) -> bool {
        self.flag(0x8000)
    }
    /// Replace only the query_or_response indication, preserving all other bits.
    pub const fn with_query_or_response(self, value: bool) -> Self {
        self.with_flag(0x8000, value)
    }
    /// CD: the query requests checking disabled.
    pub const fn checking_disabled(self) -> bool {
        self.flag(0x10)
    }
    /// Replace only the checking_disabled indication, preserving all other bits.
    pub const fn with_checking_disabled(self, value: bool) -> Self {
        self.with_flag(0x10, value)
    }
    /// AD header indication only; no DNSSEC verification is established.
    pub const fn authenticated_data(self) -> bool {
        self.flag(0x20)
    }
    /// Replace only the authenticated_data indication, preserving all other bits.
    pub const fn with_authenticated_data(self, value: bool) -> Self {
        self.with_flag(0x20, value)
    }
    /// The carried reserved bit; no automatic validation or clearing.
    pub const fn reserved_zero(self) -> bool {
        self.flag(0x40)
    }
    /// Replace only the reserved_zero indication, preserving all other bits.
    pub const fn with_reserved_zero(self, value: bool) -> Self {
        self.with_flag(0x40, value)
    }
    /// RA: the sender reports recursion available.
    pub const fn recursion_available(self) -> bool {
        self.flag(0x80)
    }
    /// Replace only the recursion_available indication, preserving all other bits.
    pub const fn with_recursion_available(self, value: bool) -> Self {
        self.with_flag(0x80, value)
    }
    /// Four-bit opcode, including unnamed values.
    pub const fn opcode(self) -> u8 {
        ((self.0 >> 11) & 15) as u8
    }
    /// Replace only the opcode; reject out-of-width values rather than truncate.
    pub const fn with_opcode(self, value: u8) -> Result<Self, Error> {
        if value > 15 {
            return Err(Error::InvalidInput);
        }
        Ok(Self((self.0 & !0x7800) | ((value as u16) << 11)))
    }
    /// Four-bit return code, including unnamed values.
    pub const fn return_code(self) -> u8 {
        (self.0 & 15) as u8
    }
    /// Replace only the return code; reject out-of-width values rather than truncate.
    pub const fn with_return_code(self, value: u8) -> Result<Self, Error> {
        if value > 15 {
            return Err(Error::InvalidInput);
        }
        Ok(Self((self.0 & !15) | value as u16))
    }
}
