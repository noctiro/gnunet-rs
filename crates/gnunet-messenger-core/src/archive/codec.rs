use super::*;
pub(super) struct Encoder {
    pub data: Zeroizing<Vec<u8>>,
    pub maximum: usize,
}
impl Encoder {
    pub fn new(maximum: usize) -> Self {
        Self {
            data: Zeroizing::new(Vec::new()),
            maximum,
        }
    }
    pub fn raw(&mut self, value: &[u8]) -> Result<(), Error> {
        let n = self
            .data
            .len()
            .checked_add(value.len())
            .ok_or(Fault::Overflow)?;
        if n > self.maximum {
            return Err(Fault::Capacity.into());
        }
        if n > self.data.capacity() {
            let target = self
                .data
                .capacity()
                .saturating_mul(2)
                .max(n)
                .min(self.maximum);
            let additional = target - self.data.len();
            self.data
                .try_reserve_exact(additional)
                .map_err(|_| Fault::Capacity)?;
            if self.data.capacity() > self.maximum {
                return Err(Fault::Capacity.into());
            }
        }
        self.data.extend_from_slice(value);
        Ok(())
    }
    pub fn u8(&mut self, v: u8) -> Result<(), Error> {
        self.raw(&[v])
    }
    pub fn bool(&mut self, v: bool) -> Result<(), Error> {
        self.u8(u8::from(v))
    }
    pub fn u64(&mut self, v: u64) -> Result<(), Error> {
        self.raw(&v.to_be_bytes())
    }
    pub fn size(&mut self, v: usize) -> Result<(), Error> {
        self.u64(u64::try_from(v).map_err(|_| Fault::Overflow)?)
    }
    pub fn bytes(&mut self, v: &[u8]) -> Result<(), Error> {
        self.size(v.len())?;
        self.raw(v)
    }
    pub fn slot(&mut self, v: Slot) -> Result<(), Error> {
        self.size(v.index)?;
        self.u64(v.generation)
    }
    pub fn opt_slot(&mut self, v: Option<Slot>) -> Result<(), Error> {
        self.bool(v.is_some())?;
        if let Some(v) = v {
            self.slot(v)?
        }
        Ok(())
    }
    pub fn opt_array<const N: usize>(&mut self, v: Option<&[u8; N]>) -> Result<(), Error> {
        self.bool(v.is_some())?;
        if let Some(v) = v {
            self.raw(v)?
        }
        Ok(())
    }
    pub fn opt_u64(&mut self, v: Option<u64>) -> Result<(), Error> {
        self.bool(v.is_some())?;
        if let Some(v) = v {
            self.u64(v)?
        }
        Ok(())
    }
    pub fn owned(&mut self, v: Option<&OwnedBytes>) -> Result<(), Error> {
        self.bool(v.is_some())?;
        if let Some(v) = v {
            self.bytes(v.expose())?
        }
        Ok(())
    }
    pub fn profile(&mut self, p: wire::profile::Profile) -> Result<(), Error> {
        self.u8(match p.endian {
            wire::profile::Endian::Little => 0,
            wire::profile::Endian::Big => 1,
        })?;
        self.size(p.file_name_bytes)
    }
    pub fn layout(&mut self, p: OriginalLayout) -> Result<(), Error> {
        match p.body {
            BodyLayout::Explicit(profile) => {
                self.u8(1)?;
                self.profile(profile)?
            }
            BodyLayout::Portable => self.u8(0)?,
        };
        self.profile(p.padding)?;
        match p.signer {
            None => self.u8(0),
            Some(OriginalSigner::Member(v)) => {
                self.u8(1)?;
                self.raw(&v)
            }
            Some(OriginalSigner::Peer(v)) => {
                self.u8(2)?;
                self.raw(&v)
            }
        }
    }
    pub fn role(&mut self, r: SourceRole) -> Result<(), Error> {
        match r {
            SourceRole::Client => self.u8(0),
            SourceRole::Peer(p) => {
                self.u8(1)?;
                self.raw(&p)
            }
            SourceRole::ServiceSigner(p) => {
                self.u8(2)?;
                self.raw(&p)
            }
        }
    }
    pub fn source(&mut self, s: SourceObservation) -> Result<(), Error> {
        self.slot(s.room)?;
        self.slot(s.source)?;
        self.role(s.role)
    }
}
pub(super) struct Decoder<'a> {
    input: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Fault::Overflow)?;
        let value = self.input.get(self.at..end).ok_or(Fault::Truncated)?;
        self.at = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.raw(N)?.try_into().map_err(|_| Fault::Malformed.into())
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Fault::Malformed.into()),
        }
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn size(&mut self, max: usize) -> Result<usize, Error> {
        let n = usize::try_from(self.u64()?).map_err(|_| Fault::Overflow)?;
        if n > max {
            return Err(Fault::Capacity.into());
        }
        Ok(n)
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.size(max)?;
        self.raw(n)
    }
    pub fn slot(&mut self, max: usize) -> Result<Slot, Error> {
        let index = self.size(max.checked_sub(1).ok_or(Fault::Capacity)?)?;
        let generation = self.u64()?;
        if generation == 0 {
            return Err(Fault::Malformed.into());
        }
        Ok(Slot { index, generation })
    }
    pub fn opt_slot(&mut self, max: usize) -> Result<Option<Slot>, Error> {
        if self.bool()? {
            Ok(Some(self.slot(max)?))
        } else {
            Ok(None)
        }
    }
    pub fn opt_array<const N: usize>(&mut self) -> Result<Option<[u8; N]>, Error> {
        if self.bool()? {
            Ok(Some(self.array()?))
        } else {
            Ok(None)
        }
    }
    pub fn opt_u64(&mut self) -> Result<Option<u64>, Error> {
        if self.bool()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }
    pub fn owned(&mut self, max: usize) -> Result<Option<OwnedBytes>, Error> {
        if self.bool()? {
            Ok(Some(OwnedBytes::copy_from(self.bytes(max)?)?))
        } else {
            Ok(None)
        }
    }
    pub fn profile(&mut self) -> Result<wire::profile::Profile, Error> {
        let endian = match self.u8()? {
            0 => wire::profile::Endian::Little,
            1 => wire::profile::Endian::Big,
            _ => return Err(Fault::Malformed.into()),
        };
        let file_name_bytes = self.size(65535 - 64)?;
        let p = wire::profile::Profile {
            endian,
            file_name_bytes,
        };
        p.validate()?;
        Ok(p)
    }
    pub fn layout(&mut self) -> Result<OriginalLayout, Error> {
        let body = match self.u8()? {
            0 => BodyLayout::Portable,
            1 => BodyLayout::Explicit(self.profile()?),
            _ => return Err(Fault::Malformed.into()),
        };
        let padding = self.profile()?;
        let signer = match self.u8()? {
            0 => None,
            1 => Some(OriginalSigner::Member(self.array()?)),
            2 => Some(OriginalSigner::Peer(self.array()?)),
            _ => return Err(Fault::Malformed.into()),
        };
        let p = OriginalLayout {
            body,
            padding,
            signer,
        };
        p.validate()?;
        Ok(p)
    }
    pub fn role(&mut self) -> Result<SourceRole, Error> {
        match self.u8()? {
            0 => Ok(SourceRole::Client),
            1 => Ok(SourceRole::Peer(self.array()?)),
            2 => Ok(SourceRole::ServiceSigner(self.array()?)),
            _ => Err(Fault::Malformed.into()),
        }
    }
    pub fn source(&mut self) -> Result<SourceObservation, Error> {
        Ok(SourceObservation {
            room: self.slot(usize::MAX)?,
            source: self.slot(usize::MAX)?,
            role: self.role()?,
        })
    }
    pub fn end(self) -> Result<(), Error> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(Fault::Malformed.into())
        }
    }
}
pub(super) fn pad(v: wire::padding::Decode) -> u8 {
    match v {
        wire::padding::Decode::Absent => 0,
        wire::padding::Decode::Required => 1,
        wire::padding::Decode::Detect => 2,
    }
}
pub(super) fn read_pad(r: &mut Decoder<'_>) -> Result<wire::padding::Decode, Error> {
    match r.u8()? {
        0 => Ok(wire::padding::Decode::Absent),
        1 => Ok(wire::padding::Decode::Required),
        2 => Ok(wire::padding::Decode::Detect),
        _ => Err(Fault::Malformed.into()),
    }
}
pub(super) fn phase(v: MessagePhase) -> u8 {
    match v {
        MessagePhase::AwaitingSender => 0,
        MessagePhase::AwaitingParents => 1,
        MessagePhase::AwaitingEpoch => 2,
        MessagePhase::Ready => 3,
        MessagePhase::Applied => 4,
        MessagePhase::Deleted => 5,
        MessagePhase::Rejected => 6,
    }
}
pub(super) fn read_phase(r: &mut Decoder<'_>) -> Result<MessagePhase, Error> {
    match r.u8()? {
        0 => Ok(MessagePhase::AwaitingSender),
        1 => Ok(MessagePhase::AwaitingParents),
        2 => Ok(MessagePhase::AwaitingEpoch),
        3 => Ok(MessagePhase::Ready),
        4 => Ok(MessagePhase::Applied),
        5 => Ok(MessagePhase::Deleted),
        6 => Ok(MessagePhase::Rejected),
        _ => Err(Fault::Malformed.into()),
    }
}
pub(super) fn session_phase(v: SessionPhase) -> u8 {
    match v {
        SessionPhase::Joining => 0,
        SessionPhase::Active => 1,
        SessionPhase::Closing => 2,
        SessionPhase::Completed => 3,
    }
}
pub(super) fn read_session_phase(r: &mut Decoder<'_>) -> Result<SessionPhase, Error> {
    match r.u8()? {
        0 => Ok(SessionPhase::Joining),
        1 => Ok(SessionPhase::Active),
        2 => Ok(SessionPhase::Closing),
        3 => Ok(SessionPhase::Completed),
        _ => Err(Fault::Malformed.into()),
    }
}
