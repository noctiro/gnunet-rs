//! GStreamer PCM provider at the same boundary as PulseAudio and WASAPI.
mod abi;
mod pipeline;

use super::{Direction, Finish};
use crate::{DECODE_SAMPLES, Error, RATE, error::retain_cleanup};
use gnunet_types::Error as Fault;
use pipeline::{Event, Owned, Pipeline, nanos};
use std::{
    ffi::CString,
    ptr::{self, NonNull},
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(30);
const WAIT_LIMIT: Duration = Duration::from_secs(5);
const CAPTURE_QUEUE: usize = 4;
const MAX_WRITE: usize = DECODE_SAMPLES * 2 * size_of::<f32>();
const PLAYBACK_QUEUE: usize = 4 * MAX_WRITE;
const BUFFER_DISCONT: u32 = 1 << 6;
const BUFFER_CORRUPTED: u32 = 1 << 8;
const FLOW_OK: i32 = 0;

fn description(direction: Direction, channels: u8) -> Result<CString, Error> {
    let caps =
        format!("audio/x-raw,format=F32LE,layout=interleaved,rate={RATE},channels={channels}");
    let text = match direction {
        Direction::Capture => format!(
            "autoaudiosrc name=gnunet_device ! audioconvert ! audioresample ! {caps} ! \
             appsink name=gnunet_pcm max-buffers={CAPTURE_QUEUE} enable-last-sample=false \
             sync=false wait-on-eos=false"
        ),
        // Feeding a byte segment to rawaudioparse gives consecutive native
        // timestamps from the exact sample count, independent of helper writes.
        Direction::Playback => format!(
            "appsrc name=gnunet_pcm format=bytes block=false max-bytes={PLAYBACK_QUEUE} \
             caps=\"{caps}\" ! rawaudioparse use-sink-caps=true ! audioconvert ! audioresample ! \
             autoaudiosink name=gnunet_device"
        ),
    };
    CString::new(text).map_err(|_| Fault::InvalidInput.into())
}

struct Sample {
    _owner: Owned,
    buffer: NonNull<std::ffi::c_void>,
    used: usize,
    length: usize,
}

enum Port {
    Capture(Option<Sample>),
    Playback,
    Closed,
}

pub(crate) struct Device {
    port: Port,
    pipeline: Pipeline,
    frame_bytes: usize,
    discontinuities: u64,
}

impl Device {
    pub(crate) fn new(direction: Direction, channels: u8) -> Result<Self, Error> {
        if !(1..=2).contains(&channels) {
            return Err(Fault::Unsupported.into());
        }
        Ok(Self {
            port: match direction {
                Direction::Capture => Port::Capture(None),
                Direction::Playback => Port::Playback,
            },
            pipeline: Pipeline::open(direction, &description(direction, channels)?)?,
            frame_bytes: usize::from(channels) * size_of::<f32>(),
            discontinuities: 0,
        })
    }

    pub(crate) fn take_discontinuities(&mut self) -> u64 {
        std::mem::take(&mut self.discontinuities)
    }

    pub(crate) fn read(&mut self, mut output: &mut [u8]) -> Result<(), Error> {
        let Port::Capture(sample) = &mut self.port else {
            return Err(Fault::InvalidInput.into());
        };
        if !output.len().is_multiple_of(self.frame_bytes) {
            return Err(Fault::InvalidInput.into());
        }
        let hard = deadline()?;
        while !output.is_empty() {
            self.pipeline.require_live()?;
            let remaining = wait_before(hard)?;
            if sample.is_none() {
                if let Some((observed, discontinuity)) =
                    pull(&self.pipeline, self.frame_bytes, remaining)?
                {
                    *sample = Some(observed);
                    if discontinuity {
                        crate::increment(&mut self.discontinuities, 1)?;
                    }
                } else {
                    continue;
                }
            }
            let retained = sample.as_mut().ok_or(Fault::NotReady)?;
            let count = output.len().min(retained.length - retained.used);
            let (prefix, rest) = output.split_at_mut(count);
            // SAFETY: The original sample still retains this exact buffer. The
            // requested initialized region stays within the checked sample and
            // the destination's exclusive byte borrow is exactly count bytes.
            let copied = unsafe {
                (self.pipeline.api.extract)(
                    retained.buffer.as_ptr(),
                    retained.used,
                    prefix.as_mut_ptr().cast(),
                    count,
                )
            };
            if copied != count {
                return Err(Fault::Io.into());
            }
            retained.used += count;
            output = rest;
            if retained.used == retained.length {
                *sample = None;
            }
        }
        Ok(())
    }

    pub(crate) fn write(&mut self, input: &[u8]) -> Result<(), Error> {
        if !matches!(self.port, Port::Playback) || !input.len().is_multiple_of(self.frame_bytes) {
            return Err(Fault::InvalidInput.into());
        }
        if input.len() > MAX_WRITE {
            return Err(Fault::Capacity.into());
        }
        if input.is_empty() {
            return Ok(());
        }
        let hard = deadline()?;
        let room = u64::try_from(PLAYBACK_QUEUE - input.len()).map_err(|_| Fault::Overflow)?;
        let api = &self.pipeline.api;
        let source = self.pipeline.endpoint.as_ptr();
        loop {
            self.pipeline.require_live()?;
            let remaining = wait_before(hard)?;
            // SAFETY: The original live endpoint is the fixed appsrc. This
            // helper is the sole producer and downstream can only free space.
            let queued = unsafe { (api.queued)(source) };
            if queued <= room {
                break;
            }
            if matches!(self.pipeline.event(remaining)?, Event::End) {
                return Err(Fault::Closed.into());
            }
        }
        // SAFETY: Use the original core's default allocator and one checked
        // bounded PCM size. The non-null result owns one mutable buffer.
        let raw = unsafe { (api.allocate)(ptr::null_mut(), input.len(), ptr::null_mut()) };
        let buffer = Owned::mini(api, raw).ok_or(Fault::Capacity)?;
        // SAFETY: Copy the exact caller-owned initialized slice into the sole
        // reference to the just-allocated native buffer.
        let copied = unsafe { (api.fill)(buffer.as_ptr(), 0, input.as_ptr().cast(), input.len()) };
        if copied != input.len() {
            return Err(Fault::Io.into());
        }
        // SAFETY: The nonblocking appsrc accepts ownership of the original
        // buffer even if native queue admission fails.
        let result = unsafe { (api.push)(source, buffer.into_raw()) };
        if result != FLOW_OK {
            return Err(self.pipeline.failure("push PCM", result));
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, action: Finish) -> Result<(), Error> {
        let port = std::mem::replace(&mut self.port, Port::Closed);
        let result = if matches!(port, Port::Playback) && action == Finish::Drain {
            self.drain()
        } else {
            Ok(())
        };
        drop(port);
        retain_cleanup(result, self.pipeline.stop())
    }

    fn drain(&self) -> Result<(), Error> {
        self.pipeline.require_live()?;
        // SAFETY: This is the sole final production request on the original
        // playback appsrc. The pipeline and its bus remain alive until EOS.
        let result = unsafe { (self.pipeline.api.end_source)(self.pipeline.endpoint.as_ptr()) };
        if result != FLOW_OK {
            return Err(self.pipeline.failure("end PCM stream", result));
        }
        match self.pipeline.event(WAIT_LIMIT)? {
            Event::End => Ok(()),
            Event::Waiting => Err(Fault::Deadline.into()),
        }
    }
}

fn pull(
    pipeline: &Pipeline,
    frame_bytes: usize,
    wait: Duration,
) -> Result<Option<(Sample, bool)>, Error> {
    let api = &pipeline.api;
    let sink = pipeline.endpoint.as_ptr();
    // SAFETY: This is the original live capture appsink. A non-null sample
    // represents one transferred native reference.
    let raw = unsafe { (api.pull)(sink, nanos(wait)) };
    let Some(owner) = Owned::mini(api, raw) else {
        pipeline.require_live()?;
        // SAFETY: Query only the same live capture endpoint.
        if unsafe { (api.sink_eos)(sink) } != 0 {
            return Err(Fault::Closed.into());
        }
        return Ok(None);
    };
    // SAFETY: The sample owns the original GstBuffer. Keep the same sample
    // alive through all access, including a partially consumed read.
    let buffer =
        NonNull::new(unsafe { (api.sample_buffer)(owner.as_ptr()) }).ok_or(Fault::Malformed)?;
    // SAFETY: The same retained immutable buffer has initialized metadata.
    let (length, flags) = unsafe { ((api.size)(buffer.as_ptr()), (api.flags)(buffer.as_ptr())) };
    if length == 0 || !length.is_multiple_of(frame_bytes) || flags & BUFFER_CORRUPTED != 0 {
        return Err(Fault::Malformed.into());
    }
    // Limit the retained original sample to one second of PCM.
    if length > RATE as usize * frame_bytes {
        return Err(Fault::Capacity.into());
    }
    Ok(Some((
        Sample {
            _owner: owner,
            buffer,
            used: 0,
            length,
        },
        flags & BUFFER_DISCONT != 0,
    )))
}

fn deadline() -> Result<Instant, Error> {
    Instant::now()
        .checked_add(WAIT_LIMIT)
        .ok_or_else(|| Fault::Overflow.into())
}

fn wait_before(hard: Instant) -> Result<Duration, Error> {
    hard.checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .map(|left| POLL.min(left))
        .ok_or_else(|| Fault::Deadline.into())
}
