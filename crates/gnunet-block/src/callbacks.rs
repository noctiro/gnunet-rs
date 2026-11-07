//! Extensible pure Rust equivalent of the public block-plugin callback table.
//!
//! The registry owns its plugin objects and drops them on context destruction;
//! each object's `Drop` replaces its unload/closure destructor. Callers can use
//! an enum to combine different plugin implementations without allocation. The
//! same enum supplies its group family. Groups borrow caller storage and the
//! registry, so context destruction cannot invalidate a live callback owner.
//! No native shared-object ABI, `void *`, varargs or unbounded sentinel scan is
//! exposed. Associated `Creation` values carry a plugin's typed varargs instead.
use crate::{
    BlockType, GroupState, Hash, ReplyEvaluation, ReturnValue,
    bloom::{BloomGroup, NativeEndian},
    plugins::{Clock, Context, GroupSizing, KeyResult, Plugin, Work},
};
use gnunet_types::Error;
/// Borrowed validation routing for a wrapper plugin. This grants no signature,
/// key or source authority; the selected nested handler still performs its own
/// actual callback. Wrapper(None) leaves terminal/malformed handling to its owner.
#[derive(Clone, Copy, Debug)]
pub enum Delegation<'a> {
    /// Invoke this plugin directly, preserving the original callback inputs.
    Direct,
    /// This plugin wraps a possible nested type and original payload slice.
    Wrapper(Option<(BlockType, &'a [u8])>),
}
/// Plugin-specific implementation of every public `PluginFunctions` callback.
/// Interior mutability, when needed for closure state, remains caller-owned;
/// sharing across threads is allowed only when the concrete implementation is Sync.
pub trait PluginFunctions {
    /// A type-safe replacement for plugin-specific create varargs.
    type Creation<'a>
    where
        Self: 'a;
    /// One concrete callback family, with caller/context lifetime preserved.
    type Group<'a>: GroupState
    where
        Self: 'a;
    /// Concrete supported types. ANY is a sentinel and is never dispatched.
    /// Unlike the C array, this slice has an explicit end and needs no sentinel.
    fn types(&self) -> &[BlockType];
    /// Optional borrowed nested validation. The complete registry resolves the
    /// nested type; a single plugin object must not invent another registry.
    /// Query, key and group callbacks keep their original outer-type contract.
    fn delegation<'a>(&self, _kind: BlockType, _block: &'a [u8]) -> Delegation<'a> {
        Delegation::Direct
    }
    /// Optional creation callback; return None when groups are unsupported.
    fn create_group<'a>(
        &'a self,
        kind: BlockType,
        creation: Self::Creation<'a>,
        raw: Option<&'a [u8]>,
        fresh_nonce: u32,
        storage: &'a mut [u8],
        profile: NativeEndian,
    ) -> Result<Option<Self::Group<'a>>, Error>;
    /// Obtain key/status independently of validation.
    fn get_key(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<KeyResult, Error>;
    /// Query validation, retaining NULL versus present-empty extended query.
    fn check_query(&self, kind: BlockType, query: &Hash, xquery: Option<&[u8]>) -> ReturnValue;
    /// Block validation.
    fn check_block(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReturnValue, Error>;
    /// Reply classification, retaining a possibly absent group.
    fn check_reply<'a>(
        &self,
        kind: BlockType,
        group: Option<&mut Self::Group<'a>>,
        request: Reply<'_>,
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReplyEvaluation, Error>
    where
        Self: 'a;
}
/// The three immutable reply inputs travel together; no copied wire or signature
/// authority is implied by constructing this view.
#[derive(Clone, Copy, Debug)]
pub struct Reply<'a> {
    /// Original query hash.
    pub query: &'a Hash,
    /// NULL and a present empty CString remain distinct for REGEX.
    pub xquery: Option<&'a [u8]>,
    /// Complete reply bytes.
    pub block: &'a [u8],
}
/// Fixed-size owning registry. First matching plugin wins, as in block.c.
///
/// A live group cannot outlast its registry or its storage:
/// ```compile_fail
/// use gnunet_block::{BlockType,GroupState,callbacks::CallbackContext,plugins::{Plugin,GroupSizing},bloom::NativeEndian};
/// let context=CallbackContext::new([Plugin::Test],NativeEndian::native());
/// let mut bytes=[0;8];
/// let group=context.create_group(BlockType::TEST,GroupSizing::FilterBytes(8),Some(&[0;4]),0,&mut bytes).unwrap().unwrap();
/// drop(context);
/// assert_eq!(group.block_type(),BlockType::TEST);
/// ```
/// The corresponding valid lifetime releases the group before its context:
/// ```
/// # fn main()->Result<(),gnunet_types::Error>{
/// use gnunet_block::{BlockType,GroupState,callbacks::CallbackContext,plugins::{Plugin,GroupSizing},bloom::NativeEndian};
/// let context=CallbackContext::new([Plugin::Test],NativeEndian::native());
/// let mut bytes=[0;8];
/// let group=context.create_group(BlockType::TEST,GroupSizing::FilterBytes(8),Some(&[0;4]),0,&mut bytes)?.ok_or(gnunet_types::Error::NotReady)?;
/// assert_eq!(group.block_type(),BlockType::TEST);
/// # Ok(()) }
/// ```
pub struct CallbackContext<P, const N: usize> {
    plugins: [P; N],
    profile: NativeEndian,
}
impl<P: PluginFunctions, const N: usize> CallbackContext<P, N> {
    /// Own the installed Rust plugin objects in their explicit load order.
    #[must_use]
    pub const fn new(plugins: [P; N], profile: NativeEndian) -> Self {
        Self { plugins, profile }
    }
    fn find(&self, kind: BlockType) -> Option<&P> {
        if kind == BlockType::ANY {
            return None;
        }
        self.plugins.iter().find(|p| {
            p.types()
                .iter()
                .take_while(|t| **t != BlockType::ANY)
                .any(|t| *t == kind)
        })
    }
    /// Invoke the first registered creation callback, preserving its lifetime.
    pub fn create_group<'a>(
        &'a self,
        kind: BlockType,
        creation: P::Creation<'a>,
        raw: Option<&'a [u8]>,
        fresh_nonce: u32,
        storage: &'a mut [u8],
    ) -> Result<Option<P::Group<'a>>, Error> {
        let Some(plugin) = self.find(kind) else {
            return Ok(None);
        };
        plugin.create_group(kind, creation, raw, fresh_nonce, storage, self.profile)
    }
    /// Dispatch key lookup; absent type returns SYSERR and leaves key untouched.
    pub fn get_key(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<KeyResult, Error> {
        self.find(kind).map_or(
            Ok(KeyResult {
                status: ReturnValue::SysErr,
                key: None,
            }),
            |p| p.get_key(kind, block, work, clock),
        )
    }
    /// Dispatch query validation, excluding ANY.
    pub fn check_query(&self, kind: BlockType, query: &Hash, xquery: Option<&[u8]>) -> ReturnValue {
        self.find(kind)
            .map_or(ReturnValue::SysErr, |p| p.check_query(kind, query, xquery))
    }
    /// Dispatch block validation.
    pub fn check_block(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReturnValue, Error> {
        let (mut kind, mut block) = (kind, block);
        for depth in 0..=crate::plugins::MAX_CONSENSUS_NESTING {
            let Some(plugin) = self.find(kind) else {
                return Ok(ReturnValue::SysErr);
            };
            match plugin.delegation(kind, block) {
                Delegation::Direct => return plugin.check_block(kind, block, work, clock),
                Delegation::Wrapper(nested) => {
                    if depth == crate::plugins::MAX_CONSENSUS_NESTING {
                        return Err(Error::Capacity);
                    }
                    match nested {
                        Some((next, bytes)) => {
                            kind = next;
                            block = bytes;
                        }
                        None => return plugin.check_block(kind, block, work, clock),
                    }
                }
            }
        }
        Err(Error::Capacity)
    }
    /// Dispatch reply classification, preserving original group and inputs.
    pub fn check_reply<'a>(
        &self,
        kind: BlockType,
        group: Option<&mut P::Group<'a>>,
        request: Reply<'_>,
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReplyEvaluation, Error>
    where
        P: 'a,
    {
        let (mut kind, mut request) = (kind, request);
        for depth in 0..=crate::plugins::MAX_CONSENSUS_NESTING {
            let Some(plugin) = self.find(kind) else {
                return Ok(ReplyEvaluation::Unsupported);
            };
            match plugin.delegation(kind, request.block) {
                Delegation::Direct => {
                    return plugin.check_reply(kind, group, request, work, clock);
                }
                Delegation::Wrapper(nested) => {
                    if depth == crate::plugins::MAX_CONSENSUS_NESTING {
                        return Err(Error::Capacity);
                    }
                    match nested {
                        Some((next, bytes)) => {
                            kind = next;
                            request.block = bytes;
                        }
                        None => return plugin.check_reply(kind, group, request, work, clock),
                    }
                }
            }
        }
        Err(Error::Capacity)
    }
}
impl PluginFunctions for Plugin {
    type Creation<'a> = GroupSizing;
    type Group<'a> = BloomGroup<'a>;
    fn types(&self) -> &[BlockType] {
        match self {
            Self::Test => &[BlockType::TEST],
            Self::Dht => &[BlockType::DHT_HELLO],
            Self::Fs => &[
                BlockType::FS_DBLOCK,
                BlockType::FS_IBLOCK,
                BlockType::FS_UBLOCK,
            ],
            Self::Gns => &[BlockType::GNS_NAMERECORD],
            Self::Dns => &[BlockType::DNS],
            Self::Regex => &[BlockType::REGEX, BlockType::REGEX_ACCEPT],
            Self::Revocation(_) => &[BlockType::REVOCATION],
            Self::SetTest => &[BlockType::SET_TEST],
            Self::Consensus => &[BlockType::CONSENSUS_ELEMENT],
            Self::SetIntersection => &[BlockType::SETI_TEST],
            Self::SetUnion => &[BlockType::SETU_TEST],
        }
    }
    fn delegation<'a>(&self, kind: BlockType, block: &'a [u8]) -> Delegation<'a> {
        if *self != Self::Consensus || kind != BlockType::CONSENSUS_ELEMENT {
            return Delegation::Direct;
        }
        Delegation::Wrapper(crate::plugins::consensus_body(block).and_then(
            |(nested, marker, body)| {
                (marker == 0 && nested != 0).then_some((BlockType(u32::from(nested)), body))
            },
        ))
    }
    fn create_group<'a>(
        &'a self,
        kind: BlockType,
        creation: GroupSizing,
        raw: Option<&'a [u8]>,
        fresh_nonce: u32,
        storage: &'a mut [u8],
        profile: NativeEndian,
    ) -> Result<Option<BloomGroup<'a>>, Error> {
        Context::new(core::slice::from_ref(self), profile).create_group(
            kind,
            creation,
            raw,
            fresh_nonce,
            storage,
        )
    }
    fn get_key(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<KeyResult, Error> {
        Context::new(core::slice::from_ref(self), NativeEndian::native())
            .get_key(kind, block, work, clock)
    }
    fn check_query(&self, kind: BlockType, query: &Hash, xquery: Option<&[u8]>) -> ReturnValue {
        Context::new(core::slice::from_ref(self), NativeEndian::native()).check_query(
            kind,
            query,
            xquery.unwrap_or_default(),
        )
    }
    fn check_block(
        &self,
        kind: BlockType,
        block: &[u8],
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReturnValue, Error> {
        Context::new(core::slice::from_ref(self), NativeEndian::native())
            .check_block(kind, block, work, clock)
    }
    fn check_reply<'a>(
        &self,
        kind: BlockType,
        group: Option<&mut BloomGroup<'a>>,
        request: Reply<'_>,
        work: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReplyEvaluation, Error>
    where
        Self: 'a,
    {
        Context::new(core::slice::from_ref(self), NativeEndian::native()).check_reply(
            kind,
            group,
            request.query,
            request.xquery,
            request.block,
            work,
            clock,
        )
    }
}
