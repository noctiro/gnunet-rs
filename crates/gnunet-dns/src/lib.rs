//! Bounded DNS packet operations corresponding to GNUnet DNSPARSER.
//! Wire names retain lossless byte labels. Native text conversion requires an
//! explicit complete Idna backend, supplied by the companion gnunet-idna crate.
//! No ASCII or browser-default backend is silently selected.
//! UTC, object slots, arena storage and work limits belong to the caller. Parsing
//! may consume arena space on error, but publishes no partial typed result.
//! Every output encoder preflights completely; errors leave output unchanged.
//!
//! Live views prevent caller storage from being overwritten:
//!
//! ```compile_fail,E0499
//! use gnunet_dns::{Arena, Name};
//! let mut bytes = [0; 64];
//! let mut arena = Arena::new(&mut bytes);
//! let name = Name::from_dotted(b"example", &mut arena).unwrap();
//! bytes.fill(0);
//! assert_eq!(name.wire(), b"\x07example\0");
//! ```
//!
//! Ending all views permits the same bytes to be reused:
//!
//! ```
//! use gnunet_dns::{Arena, Name};
//! let mut bytes = [0; 64];
//! {
//!     let mut arena = Arena::new(&mut bytes);
//!     let name = Name::from_dotted(b"example", &mut arena).unwrap();
//!     assert_eq!(name.wire(), b"\x07example\0");
//! }
//! bytes.fill(0);
//! assert!(bytes.iter().all(|byte| *byte == 0));
//! ```
#![no_std]
#![forbid(unsafe_code)]
pub mod dnssec;
mod header;
mod hex;
mod name;
mod native;
mod packet;
mod record;
pub use gnunet_types::Error;
pub use gnunet_wire::official::AbsoluteTime;
pub use header::{Flags, Header, class, opcode, return_code};
pub use hex::{decode_hex_native, encode_hex_lower};
pub use name::{Idna, Name, check_label, check_name};
pub use native::{NativePackReport, NativeScratch};
pub use packet::{Counts, PackReport, Packet, Query, Reader};
pub use record::{CaaHeader, Cert, Mx, RData, Record, Soa, Srv, Uri, cert_algorithm, cert_type};
/// Numeric public DNS assignment HEADER_LEN=12.
pub const HEADER_LEN: usize = 12;
/// Numeric public DNS assignment MAX_LABEL_LENGTH=63.
pub const MAX_LABEL_LENGTH: usize = 63;
/// Numeric public DNS assignment MAX_NAME_LENGTH=253.
pub const MAX_NAME_LENGTH: usize = 253;
/// Numeric public DNS assignment MAX_WIRE_NAME_LENGTH=255.
pub const MAX_WIRE_NAME_LENGTH: usize = 255;
/// Numeric public DNS assignment MAX_COMPRESSION_HOPS=33.
pub const MAX_COMPRESSION_HOPS: usize = 33;
/// Finite parser resource/work limits, in addition to DNS widths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Finite caller input/storage/work ceilings, in addition to DNS wire widths.
pub struct Limits {
    /// Maximum complete packet bytes inspected.
    pub maximum_packet_bytes: usize,
    /// Maximum counted queries admitted.
    pub maximum_queries: usize,
    /// Maximum total records across answer, authority and additional sections.
    pub maximum_records: usize,
    /// Caller pointer-hop ceiling; the native hard maximum33 still applies.
    pub maximum_compression_hops: usize,
    /// Byte/label/pointer work budget for one Reader.
    pub maximum_work: usize,
    /// Maximum native text bytes sent to the explicit IDNA backend.
    pub maximum_text_input_bytes: usize,
}
impl Limits {
    /// Finite native DNS-width limits with bounded parsing work.
    pub const DNS: Self = Self {
        maximum_packet_bytes: 65535,
        maximum_queries: 65535,
        maximum_records: 196605,
        maximum_compression_hops: 33,
        maximum_work: 8388608,
        maximum_text_input_bytes: 65535,
    };
}
/// Safe bump arena: future allocations are disjoint from every previous borrow.
/// Safe disjoint bump storage for public DNS names and payloads.
pub struct Arena<'a> {
    free: &'a mut [u8],
    used: usize,
}
impl<'a> Arena<'a> {
    /// Construct the explicit caller-owned view/state without allocating.
    pub fn new(storage: &'a mut [u8]) -> Self {
        Self {
            free: storage,
            used: 0,
        }
    }
    /// Number of arena bytes committed so far.
    pub const fn used(&self) -> usize {
        self.used
    }
    /// Unused arena byte capacity.
    pub fn remaining(&self) -> usize {
        self.free.len()
    }
    /// Copy into disjoint arena storage; insufficient capacity changes no arena state.
    pub fn copy(&mut self, bytes: &[u8]) -> Result<&'a [u8], Error> {
        if bytes.len() > self.free.len() {
            return Err(Error::Capacity);
        }
        let free = core::mem::take(&mut self.free);
        let (part, tail) = free.split_at_mut(bytes.len());
        part.copy_from_slice(bytes);
        self.free = tail;
        self.used += bytes.len();
        Ok(part)
    }
}
/// Lossless type number. All unstructured/unknown types retain raw RDATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Lossless numeric DNS type; unrecognized values remain raw.
pub struct Type(#[doc = "Raw16-bit type number."] pub u16);
impl Type {
    /// Numeric public DNS assignment ANY=0.
    pub const ANY: Self = Self(0);
    /// Numeric public DNS assignment A=1.
    pub const A: Self = Self(1);
    /// Numeric public DNS assignment NS=2.
    pub const NS: Self = Self(2);
    /// Numeric public DNS assignment CNAME=5.
    pub const CNAME: Self = Self(5);
    /// Numeric public DNS assignment SOA=6.
    pub const SOA: Self = Self(6);
    /// Numeric public DNS assignment PTR=12.
    pub const PTR: Self = Self(12);
    /// Numeric public DNS assignment MX=15.
    pub const MX: Self = Self(15);
    /// Numeric public DNS assignment TXT=16.
    pub const TXT: Self = Self(16);
    /// Numeric public DNS assignment RP=17.
    pub const RP: Self = Self(17);
    /// Numeric public DNS assignment AFSDB=18.
    pub const AFSDB: Self = Self(18);
    /// Numeric public DNS assignment SIG=24.
    pub const SIG: Self = Self(24);
    /// Numeric public DNS assignment KEY=25.
    pub const KEY: Self = Self(25);
    /// Numeric public DNS assignment AAAA=28.
    pub const AAAA: Self = Self(28);
    /// Numeric public DNS assignment LOC=29.
    pub const LOC: Self = Self(29);
    /// Numeric public DNS assignment SRV=33.
    pub const SRV: Self = Self(33);
    /// Numeric public DNS assignment NAPTR=35.
    pub const NAPTR: Self = Self(35);
    /// Numeric public DNS assignment KX=36.
    pub const KX: Self = Self(36);
    /// Numeric public DNS assignment CERT=37.
    pub const CERT: Self = Self(37);
    /// Numeric public DNS assignment DNAME=39.
    pub const DNAME: Self = Self(39);
    /// Numeric public DNS assignment APL=42.
    pub const APL: Self = Self(42);
    /// Numeric public DNS assignment DS=43.
    pub const DS: Self = Self(43);
    /// Numeric public DNS assignment SSHFP=44.
    pub const SSHFP: Self = Self(44);
    /// Numeric public DNS assignment IPSECKEY=45.
    pub const IPSECKEY: Self = Self(45);
    /// Numeric public DNS assignment RRSIG=46.
    pub const RRSIG: Self = Self(46);
    /// Numeric public DNS assignment NSEC=47.
    pub const NSEC: Self = Self(47);
    /// Numeric public DNS assignment DNSKEY=48.
    pub const DNSKEY: Self = Self(48);
    /// Numeric public DNS assignment DHCID=49.
    pub const DHCID: Self = Self(49);
    /// Numeric public DNS assignment NSEC3=50.
    pub const NSEC3: Self = Self(50);
    /// Numeric public DNS assignment NSEC3PARAM=51.
    pub const NSEC3PARAM: Self = Self(51);
    /// Numeric public DNS assignment TLSA=52.
    pub const TLSA: Self = Self(52);
    /// Numeric public DNS assignment SMIMEA=53.
    pub const SMIMEA: Self = Self(53);
    /// Numeric public DNS assignment HIP=55.
    pub const HIP: Self = Self(55);
    /// Numeric public DNS assignment CDS=59.
    pub const CDS: Self = Self(59);
    /// Numeric public DNS assignment CDNSKEY=60.
    pub const CDNSKEY: Self = Self(60);
    /// Numeric public DNS assignment OPENPGPKEY=61.
    pub const OPENPGPKEY: Self = Self(61);
    /// Numeric public DNS assignment TKEY=249.
    pub const TKEY: Self = Self(249);
    /// Numeric public DNS assignment TSIG=250.
    pub const TSIG: Self = Self(250);
    /// Numeric public DNS assignment ALL=255.
    pub const ALL: Self = Self(255);
    /// Numeric public DNS assignment URI=256.
    pub const URI: Self = Self(256);
    /// Numeric public DNS assignment CAA=257.
    pub const CAA: Self = Self(257);
    /// Numeric public DNS assignment TA=32768.
    pub const TA: Self = Self(32768);
    /// Whether the native type uses a hostname RDATA variant.
    pub const fn is_hostname(self) -> bool {
        matches!(self.0, 2 | 5 | 12 | 39)
    }
    /// Whether the native type uses a structured RDATA variant.
    pub const fn is_structured(self) -> bool {
        self.is_hostname() || matches!(self.0, 6 | 15 | 33 | 37 | 256)
    }
}
/// Explicit-clock native TTL math, including the never sentinel and u32 narrowing.
pub const fn ttl_expiration(ttl: u32, now: AbsoluteTime) -> AbsoluteTime {
    AbsoluteTime::from_micros(now.as_micros().saturating_add((ttl as u64) * 1_000_000))
}
/// Floor remaining microseconds to seconds and retain the native32-bit result.
pub const fn expiration_ttl(expiration: AbsoluteTime, now: AbsoluteTime) -> u32 {
    let remaining = if expiration.as_micros() == u64::MAX {
        u64::MAX
    } else {
        expiration.as_micros().saturating_sub(now.as_micros())
    };
    (remaining / 1_000_000) as u32
}
