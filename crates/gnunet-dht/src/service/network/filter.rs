//! Bounded real BLOCK groups or unchanged opaque peer filter bytes.
use super::super::{Blocks, BuiltinBlocks};
use alloc::vec::Vec;
use gnunet_block::{
    BlockType, GroupState, ReplyEvaluation, ReturnValue,
    bloom::{BloomGroup, NativeEndian},
    plugins::GroupSizing,
};
use gnunet_types::Error;

/// One original route's owned group. It carries no peer/query authority.
pub struct Filter {
    kind: u32,
    bits: Vec<u8>,
    nonce: u32,
    rounds: u32,
    profile: NativeEndian,
    present: bool,
    // Opaque raw bytes are never parsed, normalized, marked or replaced with
    // a private format. Exact seen hashes are separate local route metadata.
    opaque: bool,
    seen: Vec<[u8; 64]>,
    seen_limit: usize,
}
impl Filter {
    /// Copy only actual configured BLOCK group metadata, with fallible storage.
    /// The profile must be the same explicit native profile as that context.
    pub fn from_group(
        kind: u32,
        profile: NativeEndian,
        group: Option<BloomGroup<'_>>,
    ) -> Result<Self, Error> {
        match group {
            Some(group) => Ok(Self {
                kind,
                bits: super::copy(group.bits())?,
                nonce: group.nonce(),
                rounds: group.rounds(),
                profile,
                present: true,
                opaque: false,
                seen: Vec::new(),
                seen_limit: 0,
            }),
            None => Ok(Self {
                kind,
                bits: Vec::new(),
                nonce: 0,
                rounds: 0,
                profile,
                present: false,
                opaque: false,
                seen: Vec::new(),
                seen_limit: 0,
            }),
        }
    }
    pub(super) fn opaque(
        kind: u32,
        raw: &[u8],
        profile: NativeEndian,
        seen_limit: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            kind,
            bits: super::copy(raw)?,
            nonce: 0,
            rounds: 0,
            profile,
            present: false,
            opaque: true,
            seen: Vec::new(),
            seen_limit,
        })
    }
    pub(super) fn set_seen_limit(&mut self, limit: usize) {
        self.seen_limit = limit;
    }
    pub(super) fn is_opaque(&self) -> bool {
        self.opaque
    }
    pub(super) fn has_seen(&self, hash: &[u8; 64]) -> bool {
        self.seen.contains(hash)
    }
    pub(super) fn mark_exact(&mut self, hash: &[u8; 64]) -> Result<(), Error> {
        if self.has_seen(hash) {
            return Ok(());
        }
        if self.seen.len() >= self.seen_limit {
            return Err(Error::Capacity);
        }
        self.seen
            .try_reserve_exact(1)
            .map_err(|_| Error::Capacity)?;
        self.seen.push(*hash);
        Ok(())
    }
    pub(super) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            kind: self.kind,
            bits: super::copy(&self.bits)?,
            nonce: self.nonce,
            rounds: self.rounds,
            profile: self.profile,
            present: self.present,
            opaque: self.opaque,
            seen: super::copy_hashes(&self.seen)?,
            seen_limit: self.seen_limit,
        })
    }
    /// Borrow the same original current group without creating a new nonce.
    pub fn bloom(&mut self) -> Result<Option<BloomGroup<'_>>, Error> {
        if !self.present {
            return Ok(None);
        }
        BloomGroup::borrow_existing(
            &mut self.bits,
            BlockType(self.kind),
            self.rounds,
            self.nonce,
            self.profile,
        )
        .map(Some)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.opaque {
            return super::copy(&self.bits);
        }
        if !self.present {
            return Ok(Vec::new());
        }
        let mut duplicate = self.duplicate()?;
        let mut output = super::bytes(self.bits.len().checked_add(4).ok_or(Error::Overflow)?)?;
        let Some(group) = duplicate.bloom()? else {
            return Err(Error::Stale);
        };
        let Some(written) = group.serialize_into(&mut output)? else {
            return Err(Error::Unsupported);
        };
        output.truncate(written);
        Ok(output)
    }
    pub(super) fn mark(&mut self, hash: &[u8; 64]) -> Result<(), Error> {
        if self.opaque {
            return self.mark_exact(hash);
        }
        if let Some(mut group) = self.bloom()? {
            group.mark_seen(core::slice::from_ref(hash));
        }
        Ok(())
    }
    pub(super) fn merge(&mut self, old: &Self) -> Result<(), Error> {
        for hash in &old.seen {
            self.mark_exact(hash)?;
        }
        if !self.present || !old.present {
            return Ok(());
        }
        let mut copy = old.duplicate()?;
        let Some(mut left) = self.bloom()? else {
            return Ok(());
        };
        let Some(right) = copy.bloom()? else {
            return Ok(());
        };
        // Match native merge semantics: NO still consumes the old group and
        // keeps the incoming one; no result/callback is fabricated.
        left.merge_from(&right)?;
        Ok(())
    }
}
/// Configured real BLOCK operations needed by peer routing. Local validation,
/// concrete derived-key association and original group state stay distinct.
pub trait NetworkBlocks: Blocks {
    /// Actual plugin-derived block key; None means that plugin has no key binding.
    fn derive_key(
        &mut self,
        kind: u32,
        payload: &[u8],
        now: u64,
    ) -> Result<Option<[u8; 64]>, Error>;
    /// Restore/create an actual plugin group using the exact received raw bytes.
    fn filter(
        &mut self,
        kind: u32,
        raw: Option<&[u8]>,
        storage_bytes: usize,
        nonce: u32,
        profile: NativeEndian,
    ) -> Result<Filter, Error>;
    /// Check a validated candidate while updating only this original group.
    /// ANY query rejection for this concrete candidate is Irrelevant only;
    /// real provider/operation failures must not become opaque acceptance.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original query and candidate fields, time and original group state are the exact configured BLOCK callback inputs"
    )]
    fn filtered_reply(
        &mut self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
        payload: &[u8],
        now: u64,
        filter: &mut Filter,
    ) -> Result<ReplyEvaluation, Error>;
}
impl NetworkBlocks for BuiltinBlocks<'_, '_> {
    fn derive_key(
        &mut self,
        kind: u32,
        payload: &[u8],
        now: u64,
    ) -> Result<Option<[u8; 64]>, Error> {
        let mut clock = || now;
        let result = self
            .context
            .get_key(BlockType(kind), payload, &mut self.work, &mut clock)?;
        match result.status {
            ReturnValue::Yes => result.key.ok_or(Error::Authentication).map(Some),
            ReturnValue::No => Ok(None),
            ReturnValue::SysErr => Err(Error::Unsupported),
        }
    }
    fn filter(
        &mut self,
        kind: u32,
        raw: Option<&[u8]>,
        storage_bytes: usize,
        nonce: u32,
        profile: NativeEndian,
    ) -> Result<Filter, Error> {
        let mut storage = super::bytes(storage_bytes)?;
        let size = u32::try_from(storage_bytes).map_err(|_| Error::Capacity)?;
        let group = self.context.create_group(
            BlockType(kind),
            GroupSizing::FilterBytes(size),
            raw,
            nonce,
            &mut storage,
        )?;
        Filter::from_group(kind, profile, group)
    }
    fn filtered_reply(
        &mut self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
        payload: &[u8],
        now: u64,
        filter: &mut Filter,
    ) -> Result<ReplyEvaluation, Error> {
        if !self.candidate_query_applies(requested, key, xquery, kind)? {
            return Ok(ReplyEvaluation::Irrelevant);
        }
        let mut clock = || now;
        let result = self.context.check_reply(
            BlockType(kind),
            filter.bloom()?.as_mut(),
            key,
            Some(xquery),
            payload,
            &mut self.work,
            &mut clock,
        )?;
        match result {
            // A real installed handler's unsupported operation is not absence.
            ReplyEvaluation::Unsupported => Err(Error::Unsupported),
            ReplyEvaluation::Last if requested == 0 => Ok(ReplyEvaluation::More),
            other => Ok(other),
        }
    }
}
