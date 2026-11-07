//! Installed official plugin dispatch without C ABI, heap or implicit time.
use crate::{
    BlockType, Hash, ReplyEvaluation, ReturnValue,
    bloom::{BloomGroup, NativeEndian, compute_size, test_and_set},
    pow, regex,
};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, gns, hash512};
use gnunet_types::Error;
/// Explicit wrapper validation work bound. Exceeding it is a resource error,
/// never an invalid signature or a successful opaque fallback.
pub const MAX_CONSENSUS_NESTING: usize = 32;
pub(crate) fn consensus_body(bytes: &[u8]) -> Option<(u16, u8, &[u8])> {
    let prefix = bytes.get(..3)?;
    Some((
        u16::from_be_bytes([prefix[0], prefix[1]]),
        prefix[2],
        &bytes[3..],
    ))
}
/// One operation-time clock port; called at the original validation readpoint.
pub trait Clock {
    /// Absolute UTC microseconds, with u64::MAX as the official never value.
    fn now(&mut self) -> u64;
}
impl<F: FnMut() -> u64> Clock for F {
    fn now(&mut self) -> u64 {
        self()
    }
}
/// Snapshot of the revocation plugin's two required configuration values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationConfig {
    /// Original unsigned32 WORKBITS; host parsing narrows the configured u64.
    pub matching_bits: u32,
    /// Original EPOCH_DURATION microseconds, including FOREVER.
    pub epoch_duration: u64,
}
impl RevocationConfig {
    /// The native plugin reads WORKBITS as unsigned64 and assigns it to its
    /// unsigned32 internal field. Retain that defined modulo conversion rather
    /// than silently rejecting a valid configuration number.
    #[must_use]
    pub const fn from_native_values(workbits: u64, epoch_duration: u64) -> Self {
        Self {
            matching_bits: workbits as u32,
            epoch_duration,
        }
    }
}
/// Current installed default plugin implementations. Order fixes first match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plugin {
    /// Simple opaque DHT testing data.
    Test,
    /// Signed peer HELLO.
    Dht,
    /// FS leaf/index/universal block.
    Fs,
    /// GNS encrypted record.
    Gns,
    /// DNS exit advertisement.
    Dns,
    /// Regex state and accepting block.
    Regex,
    /// Revocation, instantiated only when both official settings exist.
    Revocation(RevocationConfig),
    /// Installed old generic SET testing block24.
    SetTest,
    /// Installed active CONSENSUS wrapper block25.
    Consensus,
    /// Set intersection testing block.
    SetIntersection,
    /// Set union testing block.
    SetUnion,
}
impl Plugin {
    fn supports(self, kind: BlockType) -> bool {
        match self {
            Self::Test => kind == BlockType::TEST,
            Self::Dht => kind == BlockType::DHT_HELLO,
            Self::Fs => [
                BlockType::FS_DBLOCK,
                BlockType::FS_IBLOCK,
                BlockType::FS_UBLOCK,
            ]
            .contains(&kind),
            Self::Gns => kind == BlockType::GNS_NAMERECORD,
            Self::Dns => kind == BlockType::DNS,
            Self::Regex => [BlockType::REGEX, BlockType::REGEX_ACCEPT].contains(&kind),
            Self::Revocation(_) => kind == BlockType::REVOCATION,
            Self::SetTest => kind == BlockType::SET_TEST,
            Self::Consensus => kind == BlockType::CONSENSUS_ELEMENT,
            Self::SetIntersection => kind == BlockType::SETI_TEST,
            Self::SetUnion => kind == BlockType::SETU_TEST,
        }
    }
}
/// Typed replacement of plugin create_group varargs and sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupSizing {
    /// `seen-set-size`, using the exact unsigned32 helper.
    SeenSet(u32),
    /// `filter-size`, exact requested bytes including source's FS zero fallback.
    FilterBytes(u32),
    /// Unknown guard: source emits a diagnostic and uses8 bytes.
    Fallback,
}
/// Exact key callback effect. None leaves an existing caller key unchanged;
/// this occurs even with YES for GNS unknown zone type (helper result ignored).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyResult {
    /// Source return code, never inferred from whether key bytes exist.
    pub status: ReturnValue,
    /// Bytes actually written by the callback, if any.
    pub key: Option<Hash>,
}
/// Explicit scratch/capability profile, no global allocator or weaker fallback.
pub struct Work<'a> {
    /// HELLO canonical address storage; failed parsing may change scratch.
    pub hello: &'a mut [u8],
    /// Explicit HELLO work/input bounds.
    pub hello_limits: gnunet_hello::Limits,
    /// Exactly one official HELLO compilation profile.
    pub hello_profile: gnunet_hello::SignatureProfile,
    /// PoW workspace, at least1024 blocks only when validating revocation.
    pub pow: &'a mut [pow::Block],
}
/// Borrowed static Rust plugin registry, with one explicit native uint32 profile.
/// Destruction releases the borrow; plugin state belongs to the caller. No
/// filesystem loader or GNUnet FFI is hidden behind this context constructor.
pub struct Context<'a> {
    plugins: &'a [Plugin],
    profile: NativeEndian,
}
impl<'a> Context<'a> {
    /// Register the caller-selected installed plugins in their exact lookup order.
    #[must_use]
    pub const fn new(plugins: &'a [Plugin], profile: NativeEndian) -> Self {
        Self { plugins, profile }
    }
    fn find(&self, kind: BlockType) -> Option<Plugin> {
        self.plugins.iter().copied().find(|p| p.supports(kind))
    }
    /// Whether this selected registry has an installed handler for the type.
    /// This performs no block operation and is independent of any handler's
    /// validation result, unsupported operation, resource error or key binding.
    #[must_use]
    pub fn has_type(&self, kind: BlockType) -> bool {
        self.find(kind).is_some()
    }
    /// Create only supported Bloom groups. Caller storage need not be power-of-two;
    /// no memory is touched if the required prefix is unavailable.
    pub fn create_group<'b>(
        &self,
        kind: BlockType,
        sizing: GroupSizing,
        raw: Option<&[u8]>,
        fresh_nonce: u32,
        storage: &'b mut [u8],
    ) -> Result<Option<BloomGroup<'b>>, Error> {
        let Some(plugin) = self.find(kind) else {
            return Ok(None);
        };
        if matches!(
            plugin,
            Plugin::Revocation(_)
                | Plugin::SetIntersection
                | Plugin::SetUnion
                | Plugin::SetTest
                | Plugin::Consensus
        ) || matches!(kind, BlockType::FS_DBLOCK | BlockType::FS_IBLOCK)
        {
            return Ok(None);
        }
        let mut size = match sizing {
            GroupSizing::SeenSet(count) => compute_size(count, 16),
            GroupSizing::FilterBytes(size) => size as usize,
            GroupSizing::Fallback => 8,
        };
        if plugin == Plugin::Fs && size == 0 {
            size = raw.map_or(0, |raw| raw.len());
        }
        if storage.len() < size {
            return Err(Error::Capacity);
        }
        BloomGroup::new(
            &mut storage[..size],
            kind,
            16,
            raw,
            fresh_nonce,
            self.profile,
        )
        .map(Some)
    }
    /// Independent query validation. ANY and unavailable plugins return SYSERR.
    pub fn check_query(&self, kind: BlockType, _query: &Hash, xquery: &[u8]) -> ReturnValue {
        let Some(plugin) = self.find(kind) else {
            return ReturnValue::SysErr;
        };
        if plugin == Plugin::Consensus {
            return ReturnValue::SysErr;
        }
        if plugin == Plugin::SetTest {
            return ReturnValue::Yes;
        }
        if plugin == Plugin::Regex && kind == BlockType::REGEX {
            if xquery.is_empty() || xquery.last() == Some(&0) {
                ReturnValue::Yes
            } else {
                ReturnValue::No
            }
        } else if xquery.is_empty() {
            ReturnValue::Yes
        } else {
            ReturnValue::No
        }
    }
    /// Independent block validation, with operation-time clock read only as source
    /// requires it. Resource failure is an explicit Rust error, not invalid data.
    pub fn check_block(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut (impl Clock + ?Sized),
    ) -> Result<ReturnValue, Error> {
        let (mut kind, mut block) = (kind, block);
        for depth in 0..=MAX_CONSENSUS_NESTING {
            let Some(plugin) = self.find(kind) else {
                return Ok(ReturnValue::SysErr);
            };
            if plugin == Plugin::Consensus {
                if depth == MAX_CONSENSUS_NESTING {
                    return Err(Error::Capacity);
                }
                let Some((nested, marker, body)) = consensus_body(block) else {
                    return Ok(ReturnValue::No);
                };
                if marker != 0 || nested == 0 {
                    return Ok(ReturnValue::Yes);
                }
                kind = BlockType(u32::from(nested));
                block = body;
                continue;
            }
            return Ok(match plugin {
                Plugin::Test => ReturnValue::Yes,
                Plugin::Fs if kind != BlockType::FS_UBLOCK => ReturnValue::Yes,
                Plugin::Fs => truth(fs_valid(block)),
                Plugin::Dns => truth(dns_valid(block, clock)),
                Plugin::Gns => truth(gns_valid(block)?),
                Plugin::Dht => truth(hello_key(block, work, clock)?.is_some()),
                Plugin::Regex if kind == BlockType::REGEX => {
                    match regex::State::parse_prefix(block) {
                        Ok(state) => truth(state.check(None, None)? != ReturnValue::SysErr),
                        Err(_) => ReturnValue::No,
                    }
                }
                Plugin::Regex => truth(regex_accept_valid(block, clock)),
                Plugin::SetTest | Plugin::SetIntersection => {
                    if block.first() == Some(&0) {
                        ReturnValue::Yes
                    } else {
                        ReturnValue::SysErr
                    }
                }
                Plugin::SetUnion => truth(block.first() == Some(&0)),
                Plugin::Consensus => return Err(Error::Stale),
                Plugin::Revocation(config) => {
                    crate::revocation::check(block, config, work.pow, clock)?
                }
            });
        }
        Err(Error::Capacity)
    }
    /// Key output is explicit and may remain unchanged for source NO/SYSERR or
    /// GNS's defined ignored-helper case. Signature/key association is not added.
    pub fn get_key(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut (impl Clock + ?Sized),
    ) -> Result<KeyResult, Error> {
        let Some(plugin) = self.find(kind) else {
            return Ok(KeyResult {
                status: ReturnValue::SysErr,
                key: None,
            });
        };
        let key = match plugin {
            Plugin::Consensus => {
                return Ok(KeyResult {
                    status: ReturnValue::SysErr,
                    key: None,
                });
            }
            Plugin::Fs if kind != BlockType::FS_UBLOCK => Some(hash512(block)),
            Plugin::Fs => Some(if block.len() < 104 {
                [0; 64]
            } else {
                hash512(&block[72..104])
            }),
            Plugin::Gns => {
                if block.len() < 112 {
                    Some([0; 64])
                } else {
                    match be32(block, 4)? {
                        65536 | 65556 => Some(hash512(&block[8..40])),
                        _ => None,
                    }
                }
            }
            Plugin::Dht => Some(hello_key(block, work, clock)?.unwrap_or([0; 64])),
            Plugin::Regex if kind == BlockType::REGEX => {
                Some(regex::State::parse_prefix(block).map_or([0; 64], |state| state.key()))
            }
            Plugin::Regex => Some(if block.len() == 176 {
                block[16..80].try_into().map_err(|_| Error::Malformed)?
            } else {
                [0; 64]
            }),
            Plugin::Revocation(_) => return crate::revocation::key(block),
            Plugin::Test
            | Plugin::Dns
            | Plugin::SetIntersection
            | Plugin::SetUnion
            | Plugin::SetTest => {
                return Ok(KeyResult {
                    status: ReturnValue::No,
                    key: None,
                });
            }
        };
        Ok(KeyResult {
            status: ReturnValue::Yes,
            key,
        })
    }
    /// Source reply classification assumes prior key/block validation. It does not
    /// automatically repeat signatures/expiry except DHT HELLO's own parser path.
    /// C assertion/OOB preconditions are safe Rust errors, never executed as UB.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the separate official plugin inputs and explicit scratch/clock ports"
    )]
    pub fn check_reply(
        &self,
        kind: BlockType,
        group: Option<&mut BloomGroup<'_>>,
        query: &Hash,
        xquery: Option<&[u8]>,
        reply: &[u8],
        work: &mut Work<'_>,
        clock: &mut (impl Clock + ?Sized),
    ) -> Result<ReplyEvaluation, Error> {
        let (mut kind, mut reply) = (kind, reply);
        for depth in 0..=MAX_CONSENSUS_NESTING {
            let Some(plugin) = self.find(kind) else {
                return Ok(ReplyEvaluation::Unsupported);
            };
            if plugin == Plugin::Consensus {
                if depth == MAX_CONSENSUS_NESTING {
                    return Err(Error::Capacity);
                }
                let (nested, marker, body) = consensus_body(reply).ok_or(Error::Malformed)?;
                if marker != 0 || nested == 0 {
                    return Ok(ReplyEvaluation::More);
                }
                kind = BlockType(u32::from(nested));
                reply = body;
                continue;
            }
            let hash = match plugin {
                Plugin::Fs if kind != BlockType::FS_UBLOCK => return Ok(ReplyEvaluation::Last),
                Plugin::Revocation(_) => return Ok(ReplyEvaluation::Last),
                Plugin::Dht => match hello_key(reply, work, clock)? {
                    Some(hash) => hash,
                    None => return Ok(ReplyEvaluation::Irrelevant),
                },
                Plugin::Gns => {
                    if reply.len() < 112 || be32(reply, 0)? as usize > reply.len() {
                        return Err(Error::Malformed);
                    }
                    hash512(reply)
                }
                Plugin::Regex if kind == BlockType::REGEX => {
                    if xquery.is_some_and(|xquery| !xquery.is_empty() && xquery.last() != Some(&0))
                    {
                        return Err(Error::Malformed);
                    }
                    match regex::State::parse_prefix(reply)?.check(Some(query), xquery)? {
                        ReturnValue::Yes => hash512(reply),
                        ReturnValue::No => return Ok(ReplyEvaluation::Irrelevant),
                        ReturnValue::SysErr => return Err(Error::Malformed),
                    }
                }
                Plugin::Regex => {
                    if reply.len() != 176 || be32(reply, 0)? != 80 {
                        return Err(Error::Malformed);
                    }
                    hash512(reply)
                }
                Plugin::SetIntersection | Plugin::SetUnion | Plugin::SetTest => {
                    if reply.first() != Some(&0) {
                        return Err(Error::Malformed);
                    }
                    return Ok(ReplyEvaluation::More);
                }
                Plugin::Consensus => return Err(Error::Stale),
                Plugin::Test | Plugin::Fs | Plugin::Dns => hash512(reply),
            };
            return Ok(if test_and_set(group, &hash) {
                ReplyEvaluation::Duplicate
            } else {
                ReplyEvaluation::More
            });
        }
        Err(Error::Capacity)
    }
}
fn truth(value: bool) -> ReturnValue {
    if value {
        ReturnValue::Yes
    } else {
        ReturnValue::No
    }
}
pub(crate) fn be32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
pub(crate) fn be64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn signature(public: &[u8], purpose: u32, region: &[u8], sig: &[u8]) -> bool {
    let Ok(public) = public.try_into() else {
        return false;
    };
    let Ok(sig) = sig.try_into() else {
        return false;
    };
    EddsaPublicKey::from_bytes(public)
        .verify(purpose, region, &EddsaSignature::from_bytes(sig))
        .is_ok()
}
fn fs_valid(block: &[u8]) -> bool {
    block.len() >= 104
        && be32(block, 64).is_ok_and(|n| u64::from(n) + 64 == block.len() as u64)
        && signature(&block[72..104], 17, &block[64..], &block[..64])
}
fn dns_valid(block: &[u8], clock: &mut (impl Clock + ?Sized)) -> bool {
    block.len() == 112
        && be32(block, 64) == Ok(48)
        && be64(block, 72).is_ok_and(|expiration| expiration >= clock.now())
        && signature(&block[80..112], 11, &block[64..], &block[..64])
}
fn regex_accept_valid(block: &[u8], clock: &mut (impl Clock + ?Sized)) -> bool {
    block.len() == 176
        && be32(block, 0) == Ok(80)
        && be64(block, 8).is_ok_and(|expiration| expiration >= clock.now())
        && signature(&block[80..112], 18, &block[..80], &block[112..176])
}
fn gns_valid(block: &[u8]) -> Result<bool, Error> {
    if block.len() < 112 {
        return Ok(false);
    }
    let size = be32(block, 0)? as usize;
    if size < 112 || size > block.len() {
        return Ok(false);
    }
    let payload = &block[112..size];
    // The normal helper asserts this exact limit before allocating its purpose.
    if payload.len() > u16::MAX as usize {
        return Err(Error::TooLarge);
    }
    let signed_size = payload.len() as u32 + 16;
    let public = block[8..40].try_into().map_err(|_| Error::Truncated)?;
    let signature = block[40..104].try_into().map_err(|_| Error::Truncated)?;
    let mut prefix = [0; 16];
    prefix[..4].copy_from_slice(&signed_size.to_be_bytes());
    prefix[4..8].copy_from_slice(&15u32.to_be_bytes());
    prefix[8..].copy_from_slice(&block[104..112]);
    let parts = [&prefix[..], payload];
    Ok(match be32(block, 4)? {
        65536 => gns::verify_pkey(&public, 15, &parts, &signature).is_ok(),
        65556 => gns::verify_edkey(&public, 15, &parts, &signature).is_ok(),
        _ => false,
    })
}
fn hello_key(
    block: &[u8],
    work: &mut Work<'_>,
    clock: &mut (impl Clock + ?Sized),
) -> Result<Option<Hash>, Error> {
    let hello = match gnunet_hello::Hello::parse_block(block, work.hello, work.hello_limits) {
        Ok(value) => value,
        Err(error @ Error::Capacity) => return Err(error),
        Err(_) => return Ok(None),
    };
    if hello.verify_signature(work.hello_profile).is_err() {
        return Ok(None);
    }
    if hello.expiration().as_micros() < clock.now() {
        return Ok(None);
    }
    Ok(Some(hash512(hello.peer().as_bytes())))
}

#[cfg(test)]
#[path = "plugins_consensus_tests.rs"]
mod consensus_tests;
