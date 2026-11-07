use crate::{
    DECODE_SAMPLES, Error, Limits, Report, buffer,
    framing::Input,
    increment,
    native::{Decoder, Pulse},
    ogg::{Page, Pages, Status},
};
use gnunet_types::Error as Fault;
use std::io;
use zeroize::Zeroizing;
#[derive(Clone, Copy, Default)]
struct Span {
    start: usize,
    end: usize,
    combined: bool,
}
struct Pcm {
    samples: Zeroizing<Vec<f32>>,
    bytes: Zeroizing<Vec<u8>>,
}
impl Pcm {
    fn new() -> Self {
        Self {
            samples: Zeroizing::new(Vec::new()),
            bytes: Zeroizing::new(Vec::new()),
        }
    }
    fn prepare(&mut self, channels: usize) -> Result<(), Error> {
        self.samples = buffer::<f32>(
            DECODE_SAMPLES
                .checked_mul(channels)
                .ok_or(Fault::Overflow)?,
        )?;
        self.bytes = buffer::<u8>(
            DECODE_SAMPLES
                .checked_mul(channels)
                .and_then(|n| n.checked_mul(4))
                .ok_or(Fault::Overflow)?,
        )?;
        Ok(())
    }
}
struct Stream {
    decoder: Option<Decoder>,
    speaker: Option<Pulse>,
    channels: usize,
    phase: u8,
    skip: u64,
    pre_skip: u64,
    eos: bool,
}
impl Stream {
    fn new() -> Self {
        Self {
            decoder: None,
            speaker: None,
            channels: 0,
            phase: 0,
            skip: 0,
            pre_skip: 0,
            eos: false,
        }
    }
    fn head(
        &mut self,
        packet: &[u8],
        limits: Limits,
        pcm: &mut Pcm,
        report: &mut Report,
    ) -> Result<(), Error> {
        if packet.len() < 19
            || packet.get(..8) != Some(b"OpusHead")
            || packet[8] > 15
            || !(1..=2).contains(&packet[9])
            || packet[18] != 0
            || packet[8] == 1 && packet.len() != 19
        {
            return Err(Error::Ogg("OpusHead mapping/version/channels"));
        }
        let skip = u16::from_le_bytes([packet[10], packet[11]]);
        let gain = i16::from_le_bytes([packet[16], packet[17]]);
        if let Some(speaker) = &mut self.speaker {
            speaker.finish(true)?;
            report.drained = true;
        }
        self.speaker = None;
        self.decoder = None;
        let decoder = Decoder::new(packet[9], gain, limits)?;
        if self.phase != 0 && !self.eos {
            increment(&mut report.unterminated_streams, 1)?;
        }
        self.decoder = Some(decoder);
        self.channels = usize::from(packet[9]);
        self.phase = 1;
        self.skip = u64::from(skip);
        self.pre_skip = u64::from(skip);
        self.eos = false;
        pcm.prepare(self.channels)?;
        Ok(())
    }
    fn tags(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.phase != 1 || packet.len() < 16 || packet.get(..8) != Some(b"OpusTags") {
            return Err(Error::Ogg("OpusTags header"));
        }
        let read = |at: usize| -> Result<usize, Error> {
            let b = packet
                .get(at..at.checked_add(4).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Truncated)?;
            Ok(usize::try_from(u32::from_le_bytes(
                b.try_into().map_err(|_| Fault::Truncated)?,
            ))
            .map_err(|_| Fault::Overflow)?)
        };
        let mut at = 12usize.checked_add(read(8)?).ok_or(Fault::Overflow)?;
        let count = read(at)?;
        at = at.checked_add(4).ok_or(Fault::Overflow)?;
        if count > packet.len().saturating_sub(at) / 4 {
            return Err(Error::Ogg("OpusTags count exceeds remaining extent"));
        }
        for _ in 0..count {
            let n = read(at)?;
            at = at
                .checked_add(4)
                .and_then(|v| v.checked_add(n))
                .ok_or(Fault::Overflow)?;
            if at > packet.len() {
                return Err(Fault::Truncated.into());
            }
        }
        self.phase = 2;
        Ok(())
    }
    fn decode(
        &mut self,
        packet: &[u8],
        position: u64,
        limit: u64,
        pcm: &mut Pcm,
        report: &mut Report,
    ) -> Result<u64, Error> {
        if self.phase != 2 || self.eos {
            return Err(Error::Ogg("audio outside active Opus stream"));
        }
        let decoder = self.decoder.as_mut().ok_or(Fault::NotReady)?;
        let expected = decoder.samples(packet)?;
        let samples = decoder.decode(packet, &mut pcm.samples)?;
        if samples != expected {
            return Err(Error::Ogg("actual decoder duration disagrees with packet"));
        }
        let samples = u64::try_from(samples).map_err(|_| Fault::Overflow)?;
        increment(&mut report.decoded_samples, samples)?;
        let skip = self.skip.min(samples);
        self.skip -= skip;
        let start = position.checked_add(skip).ok_or(Fault::Overflow)?;
        let selected = (samples - skip).min(limit.saturating_sub(start));
        if selected != 0 {
            let first = usize::try_from(skip)
                .map_err(|_| Fault::Overflow)?
                .checked_mul(self.channels)
                .ok_or(Fault::Overflow)?;
            let count = usize::try_from(selected)
                .map_err(|_| Fault::Overflow)?
                .checked_mul(self.channels)
                .ok_or(Fault::Overflow)?;
            let end = first.checked_add(count).ok_or(Fault::Overflow)?;
            let output_bytes = count.checked_mul(4).ok_or(Fault::Overflow)?;
            for (value, out) in pcm
                .samples
                .get(first..end)
                .ok_or(Fault::Capacity)?
                .iter()
                .zip(pcm.bytes[..output_bytes].as_chunks_mut::<4>().0.iter_mut())
            {
                out.copy_from_slice(&value.to_le_bytes());
            }
            if self.speaker.is_none() {
                self.speaker = Some(Pulse::new(
                    false,
                    u8::try_from(self.channels).map_err(|_| Fault::Overflow)?,
                )?);
            }
            self.speaker
                .as_mut()
                .ok_or(Fault::NotReady)?
                .write(&pcm.bytes[..output_bytes])?;
            report.drained = false;
            increment(&mut report.submitted_samples, selected)?;
            pcm.bytes[..output_bytes].fill(0);
        }
        pcm.samples.fill(0.0);
        Ok(samples)
    }
    fn finish(&mut self, drain: bool, report: &mut Report) -> Result<(), Error> {
        if let Some(speaker) = &mut self.speaker {
            speaker.finish(drain)?;
            if drain {
                report.drained = true;
            }
        }
        self.speaker = None;
        self.decoder = None;
        Ok(())
    }
}
struct Player {
    stream: Stream,
    pcm: Pcm,
    pending: Zeroizing<Vec<u8>>,
    serial: Option<u32>,
    sequence: u32,
    granule: Option<u64>,
    discard: bool,
    limits: Limits,
}
impl Player {
    fn new(limits: Limits) -> Self {
        Self {
            stream: Stream::new(),
            pcm: Pcm::new(),
            pending: Zeroizing::new(Vec::new()),
            serial: None,
            sequence: 0,
            granule: None,
            discard: false,
            limits,
        }
    }
    fn clear_packet(&mut self) {
        self.pending.fill(0);
        self.pending.clear();
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let n = self
            .pending
            .len()
            .checked_add(bytes.len())
            .ok_or(Fault::Overflow)?;
        if n > self.limits.packet_bytes {
            return Err(Fault::Capacity.into());
        }
        if n > self.pending.capacity() {
            let want = self
                .pending
                .capacity()
                .saturating_mul(2)
                .max(1024)
                .max(n)
                .min(self.limits.packet_bytes);
            let additional = want - self.pending.len();
            if self.pending.try_reserve_exact(additional).is_err() {
                let fallback = n - self.pending.len();
                self.pending
                    .try_reserve_exact(fallback)
                    .map_err(|_| Fault::Capacity)?;
            }
        }
        if self.pending.capacity() > self.limits.packet_bytes {
            return Err(Fault::Capacity.into());
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }
    fn page(&mut self, page: Page<'_>, report: &mut Report) -> Result<(), Error> {
        let serial = page.serial()?;
        let sequence = page.sequence()?;
        let granule = page.granule()?;
        let bos = page.flags() & 2 != 0;
        let eos = page.flags() & 4 != 0;
        let continued = page.flags() & 1 != 0;
        if bos {
            if self.serial == Some(serial) || sequence != 0 || continued || eos {
                return Err(Error::Ogg("invalid/reused BOS stream"));
            }
            let laces = page.laces();
            let packets = laces.iter().filter(|l| **l < 255).count();
            if packets != 1 || laces.last() == Some(&255) || granule != 0 {
                return Err(Error::Ogg("OpusHead must occupy its complete own page"));
            }
            self.stream
                .head(page.body(), self.limits, &mut self.pcm, report)?;
            self.clear_packet();
            self.serial = Some(serial);
            self.sequence = 1;
            self.granule = None;
            self.discard = false;
            increment(&mut report.pages, 1)?;
            return Ok(());
        }
        if self.serial != Some(serial) {
            return Err(Error::Ogg("missing OpusHead or multiplexed foreign stream"));
        }
        if self.stream.eos {
            return Err(Error::Ogg("data after original EOS"));
        }
        let gap = sequence.wrapping_sub(self.sequence);
        if gap > 0x7fffffff {
            return Err(Error::Ogg("duplicate or backwards page sequence"));
        }
        if gap != 0 {
            increment(&mut report.lost_pages, u64::from(gap))?;
            self.clear_packet();
            self.discard = continued;
            if self.stream.phase != 2 {
                return Err(Error::Ogg("lost required Opus headers"));
            }
        } else if continued {
            if self.pending.is_empty() && !self.discard {
                if self.stream.phase == 2 && self.granule.is_none() {
                    self.discard = true;
                } else {
                    return Err(Error::Ogg("unbound continued packet"));
                }
            }
        } else if !self.pending.is_empty() || self.discard {
            return Err(Error::Ogg("missing continued flag"));
        }
        self.sequence = sequence.wrapping_add(1);
        let body = page.body();
        let mut spans = [Span::default(); 255];
        let mut count = 0usize;
        let mut completed_packets = 0usize;
        let mut at = 0usize;
        let mut start = 0usize;
        let mut combine = continued && !self.pending.is_empty();
        for lace in page.laces() {
            at = at.checked_add(usize::from(*lace)).ok_or(Fault::Overflow)?;
            if *lace < 255 {
                completed_packets += 1;
                if self.discard {
                    increment(&mut report.unrecoverable_packets, 1)?;
                    self.discard = false;
                    start = at;
                    combine = false;
                    continue;
                }
                if count == spans.len() {
                    return Err(Fault::Capacity.into());
                }
                if combine {
                    self.append(body.get(start..at).ok_or(Fault::Truncated)?)?;
                }
                spans[count] = Span {
                    start,
                    end: at,
                    combined: combine,
                };
                count += 1;
                start = at;
                combine = false;
            }
        }
        let tail = body.get(start..).ok_or(Fault::Truncated)?;
        if eos && (!tail.is_empty() || self.discard) {
            return Err(Error::Ogg("EOS with incomplete packet"));
        }
        if count == 0 {
            if !self.discard {
                self.append(tail)?;
            }
            if completed_packets != 0 {
                // A missing prefix can make a completed original packet
                // unrecoverable. Its real granule remains a valid next anchor;
                // do not synthesize PCM or mislabel it as an empty page.
                if granule == u64::MAX || self.granule.is_some_and(|previous| granule < previous) {
                    return Err(Error::Ogg("discarded packet granule"));
                }
                self.granule = Some(granule);
            }
            if eos {
                if self.stream.phase != 2
                    || !self.pending.is_empty()
                    || (completed_packets == 0
                        && granule != u64::MAX
                        && Some(granule) != self.granule)
                    || granule != u64::MAX && granule < self.stream.pre_skip
                {
                    return Err(Error::Ogg("invalid empty EOS"));
                }
                self.stream.eos = true;
                increment(&mut report.eos_streams, 1)?;
            } else if completed_packets == 0 && granule != u64::MAX {
                return Err(Error::Ogg("page without completed packet has a granule"));
            }
            increment(&mut report.pages, 1)?;
            return Ok(());
        }
        if self.stream.phase == 1 {
            if count != 1 || !tail.is_empty() || granule != 0 || eos {
                return Err(Error::Ogg("OpusTags must end on its own page"));
            }
            let span = spans[0];
            let packet = if span.combined {
                &self.pending[..]
            } else {
                body.get(span.start..span.end).ok_or(Fault::Truncated)?
            };
            self.stream.tags(packet)?;
            self.clear_packet();
            increment(&mut report.pages, 1)?;
            return Ok(());
        }
        if self.stream.phase != 2 || granule == u64::MAX {
            return Err(Error::Ogg("missing audio granule/context"));
        }
        let mut total = 0u64;
        for span in &spans[..count] {
            let packet = if span.combined {
                &self.pending[..]
            } else {
                body.get(span.start..span.end).ok_or(Fault::Truncated)?
            };
            let n = self
                .stream
                .decoder
                .as_ref()
                .ok_or(Fault::NotReady)?
                .samples(packet)?;
            total = total
                .checked_add(u64::try_from(n).map_err(|_| Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        if eos && granule < self.stream.pre_skip {
            return Err(Error::Ogg("EOS before pre-skip"));
        }
        let base = match self.granule {
            None => {
                if granule >= total {
                    granule - total
                } else if eos {
                    0
                } else {
                    return Err(Error::Ogg("initial audio granule precedes actual samples"));
                }
            }
            Some(previous) if gap != 0 || completed_packets > count => {
                if granule >= previous.checked_add(total).ok_or(Fault::Overflow)? {
                    granule - total
                } else if eos && granule >= previous {
                    previous
                } else {
                    return Err(Error::Ogg("gap granule cannot timestamp actual packets"));
                }
            }
            Some(previous) => {
                let expected = previous.checked_add(total).ok_or(Fault::Overflow)?;
                if (!eos && granule != expected)
                    || (eos && (granule < previous || granule > expected))
                {
                    return Err(Error::Ogg("noncontiguous or invalid final granule"));
                }
                previous
            }
        };
        let mut position = base;
        for span in &spans[..count] {
            let packet = if span.combined {
                &self.pending[..]
            } else {
                body.get(span.start..span.end).ok_or(Fault::Truncated)?
            };
            let n = self
                .stream
                .decode(packet, position, granule, &mut self.pcm, report)?;
            position = position.checked_add(n).ok_or(Fault::Overflow)?;
        }
        self.clear_packet();
        if !self.discard {
            self.append(tail)?;
        }
        self.granule = Some(granule);
        if eos {
            self.stream.eos = true;
            increment(&mut report.eos_streams, 1)?;
        }
        increment(&mut report.pages, 1)?;
        Ok(())
    }
    fn finish(&mut self, report: &mut Report) -> Result<(), Error> {
        if !self.pending.is_empty() || self.discard {
            return Err(Error::Truncated {
                operation: "Opus packet",
                actual: self.pending.len(),
                expected: self.pending.len().saturating_add(1),
            });
        }
        if self.serial.is_some() && self.stream.phase != 2 {
            return Err(Error::Ogg("EOF before required OpusTags"));
        }
        if self.serial.is_some() && !self.stream.eos {
            increment(&mut report.unterminated_streams, 1)?;
        }
        self.stream.finish(true, report)
    }
}
/// Run real730/Ogg/Opus playback in its independent helper process. Complete
/// live EOF without EOS is retained as a discontinuity; partial pipe/page/packet
/// EOF is a real error. Blocking provider calls require parent kill/reap bounds.
pub fn playback(limits: Limits) -> Result<Report, Error> {
    let limits = limits.validate()?;
    let stdin = io::stdin();
    let mut input = Input::new(stdin.lock(), limits)?;
    let mut pages = Pages::new(limits)?;
    let mut player = Player::new(limits);
    let mut report = Report::default();
    let outcome = (|| -> Result<(), Error> {
        while let Some(payload) = input.next_frame()? {
            increment(&mut report.frames, 1)?;
            if payload.is_empty() {
                std::thread::yield_now();
                continue;
            }
            let mut at = 0usize;
            loop {
                let (used, status) = pages.feed(&payload[at..])?;
                at = at.checked_add(used).ok_or(Fault::Overflow)?;
                match status {
                    Status::Ready => {
                        player.page(pages.page()?, &mut report)?;
                        pages.consume()?;
                    }
                    Status::Resynchronized => {
                        increment(&mut report.resynchronized_bytes, 1)?;
                    }
                    Status::NeedInput if at == payload.len() => break,
                    Status::NeedInput => {}
                }
                if used == 0 && status == Status::NeedInput {
                    return Err(Error::Ogg("page reader made no progress"));
                }
                if at == payload.len() && status == Status::Ready {
                    break;
                }
            }
        }
        pages.finish()?;
        player.finish(&mut report)
    })();
    match outcome {
        Ok(()) => Ok(report),
        Err(original) => {
            let cleanup = player.stream.finish(false, &mut report).err();
            match cleanup {
                Some(cleanup) => Err(Error::Cleanup {
                    original: Box::new(original),
                    cleanup: Box::new(cleanup),
                }),
                None => Err(original),
            }
        }
    }
}
