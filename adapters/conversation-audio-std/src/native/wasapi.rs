//! Blocking shared-mode Windows endpoints with original engine buffer loans.
//! No callback thread, copied PCM queue or implicit device replacement.
mod abi;
mod com;
use super::{Direction, Finish};
use crate::{Error, RATE};
use com::{Apartment, Object};
use gnunet_types::Error as Fault;
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Media::Audio::{
        AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY, AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_S_BUFFER_EMPTY,
        AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
        AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, MMDeviceEnumerator, WAVEFORMATEX, eCapture,
        eCommunications, eRender,
    },
    System::{
        Com::{CLSCTX_ALL, CoCreateInstance},
        Threading::{CreateEventW, WaitForSingleObject},
    },
};
fn check(operation: &'static str, code: i32) -> Result<(), Error> {
    if code < 0 {
        Err(Error::Provider {
            provider: "WASAPI",
            operation,
            code,
        })
    } else {
        Ok(())
    }
}
fn system(operation: &'static str) -> Error {
    Error::Io {
        operation,
        completed: 0,
        source: io::Error::last_os_error(),
    }
}
fn wait(event: &OwnedHandle) -> Result<(), Error> {
    // SAFETY: original owned kernel event remains live for this bounded wait.
    match unsafe { WaitForSingleObject(event.as_raw_handle() as HANDLE, 250) } {
        WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
        WAIT_FAILED => Err(system("WASAPI event wait")),
        _ => Err(Fault::Malformed.into()),
    }
}
struct Packet {
    pointer: *mut u8,
    frames: u32,
    bytes: usize,
    offset: usize,
    silent: bool,
}
enum Stream {
    Capture {
        client: Object<abi::Capture>,
        packet: Option<Packet>,
        discontinuities: u64,
    },
    Render(Object<abi::Render>),
}
pub(crate) struct Device {
    // Service interfaces release before the engine; its event and apartment
    // remain owned until after the last native interface release.
    stream: Stream,
    engine: Object<abi::Client>,
    event: OwnedHandle,
    _apartment: Apartment,
    frames: u32,
    frame_bytes: usize,
    started: bool,
}
impl Device {
    pub(crate) fn new(direction: Direction, channels: u8) -> Result<Self, Error> {
        if !(1..=2).contains(&channels) {
            return Err(Fault::Unsupported.into());
        }
        let apartment = Apartment::new()?;
        // SAFETY: unnamed auto-reset event, private to this original helper owner.
        let raw_event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if raw_event.is_null() {
            return Err(system("CreateEventW"));
        }
        // SAFETY: this successful newly created event transfers one unique handle.
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        let mut raw = ptr::null_mut();
        // SAFETY: Windows' standard endpoint enumerator and exact interface IID;
        // output is exclusive and the owning STA reference is retained above.
        check("CoCreateInstance(MMDeviceEnumerator)", unsafe {
            CoCreateInstance(
                &MMDeviceEnumerator,
                ptr::null_mut(),
                CLSCTX_ALL,
                &abi::ENUMERATOR,
                &mut raw,
            )
        })?;
        // SAFETY: successful SDK call returned this exact interface reference.
        let enumerator = unsafe { Object::<abi::Enumerator>::take(raw)? };
        raw = ptr::null_mut();
        // SAFETY: original live enumerator and initialized exclusive output.
        check("GetDefaultAudioEndpoint", unsafe {
            (enumerator.table().default)(
                enumerator.raw(),
                if direction == Direction::Capture {
                    eCapture
                } else {
                    eRender
                },
                eCommunications,
                &mut raw,
            )
        })?;
        // SAFETY: GetDefaultAudioEndpoint's result is an owned IMMDevice reference.
        let endpoint = unsafe { Object::<abi::Endpoint>::take(raw)? };
        raw = ptr::null_mut();
        // SAFETY: standard audio client IID and null activation parameters.
        check("IMMDevice::Activate(IAudioClient)", unsafe {
            (endpoint.table().activate)(
                endpoint.raw(),
                &abi::AUDIO_CLIENT,
                CLSCTX_ALL,
                ptr::null(),
                &mut raw,
            )
        })?;
        // SAFETY: exact successful IAudioClient activation reference.
        let engine = unsafe { Object::<abi::Client>::take(raw)? };
        let frame_bytes = usize::from(channels) * 4;
        let format = WAVEFORMATEX {
            wFormatTag: 3,
            nChannels: u16::from(channels),
            nSamplesPerSec: RATE,
            nAvgBytesPerSec: RATE * frame_bytes as u32,
            nBlockAlign: frame_bytes as u16,
            wBitsPerSample: 32,
            cbSize: 0,
        };
        // SAFETY: the complete standard Float32LE format is borrowed during
        // shared-mode initialization; system conversion handles device mixing.
        check("IAudioClient::Initialize", unsafe {
            (engine.table().initialize)(
                engine.raw(),
                0,
                AUDCLNT_STREAMFLAGS_EVENTCALLBACK
                    | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                    | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                1_000_000,
                0,
                &format,
                ptr::null(),
            )
        })?;
        // SAFETY: the original event outlives every reference to this engine.
        check("IAudioClient::SetEventHandle", unsafe {
            (engine.table().event)(engine.raw(), raw_event)
        })?;
        let mut frames = 0;
        // SAFETY: live initialized engine and exclusive scalar output.
        check("IAudioClient::GetBufferSize", unsafe {
            (engine.table().size)(engine.raw(), &mut frames)
        })?;
        if frames == 0 {
            return Err(Fault::Malformed.into());
        }
        raw = ptr::null_mut();
        let iid = if direction == Direction::Capture {
            &abi::CAPTURE
        } else {
            &abi::RENDER
        };
        // SAFETY: exact direction-specific service IID and exclusive output.
        check("IAudioClient::GetService", unsafe {
            (engine.table().service)(engine.raw(), iid, &mut raw)
        })?;
        let stream = if direction == Direction::Capture {
            // SAFETY: matching capture-service result and retained parent engine/apartment.
            Stream::Capture {
                // SAFETY: exact successful capture-service IID result; the
                // original engine and its apartment remain retained below.
                client: unsafe { Object::take(raw)? },
                packet: None,
                discontinuities: 0,
            }
        } else {
            // SAFETY: matching render-service result and retained parent engine/apartment.
            Stream::Render(unsafe { Object::take(raw)? })
        };
        let mut device = Self {
            stream,
            engine,
            event,
            _apartment: apartment,
            frames,
            frame_bytes,
            started: false,
        };
        if direction == Direction::Capture {
            device.start()?;
        }
        Ok(device)
    }
    fn start(&mut self) -> Result<(), Error> {
        if !self.started {
            // SAFETY: uniquely driven initialized original audio client.
            check("IAudioClient::Start", unsafe {
                (self.engine.table().start)(self.engine.raw())
            })?;
            self.started = true;
        }
        Ok(())
    }
    pub(crate) fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if !bytes.len().is_multiple_of(self.frame_bytes) {
            return Err(Fault::InvalidInput.into());
        }
        let Stream::Capture {
            client,
            packet,
            discontinuities,
        } = &mut self.stream
        else {
            return Err(Fault::InvalidInput.into());
        };
        let mut at = 0;
        while at < bytes.len() {
            if packet.is_none() {
                let mut available = 0;
                // SAFETY: original capture service and exclusive scalar output.
                check("IAudioCaptureClient::GetNextPacketSize", unsafe {
                    (client.table().next)(client.raw(), &mut available)
                })?;
                if available == 0 {
                    wait(&self.event)?;
                    continue;
                }
                let mut data = ptr::null_mut();
                let mut frames = 0;
                let mut flags = 0;
                // SAFETY: live capture interface and exclusive initialized outputs;
                // optional timestamps are omitted. Its engine owns this buffer.
                let status = unsafe {
                    (client.table().get)(
                        client.raw(),
                        &mut data,
                        &mut frames,
                        &mut flags,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                check("IAudioCaptureClient::GetBuffer", status)?;
                if status == AUDCLNT_S_BUFFER_EMPTY {
                    continue;
                } // AUDCLNT_S_BUFFER_EMPTY, no loan.
                *packet = Some(Packet {
                    pointer: data,
                    frames,
                    bytes: 0,
                    offset: 0,
                    silent: flags & AUDCLNT_BUFFERFLAGS_SILENT as u32 != 0,
                });
                let length = (frames as usize)
                    .checked_mul(self.frame_bytes)
                    .ok_or(Fault::Overflow)?;
                packet.as_mut().ok_or(Fault::NotReady)?.bytes = length;
                if frames == 0
                    || frames > self.frames
                    || (!packet.as_ref().is_some_and(|p| p.silent) && data.is_null())
                {
                    return Err(Fault::Malformed.into());
                }
                if flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY as u32 != 0 {
                    *discontinuities = discontinuities.checked_add(1).ok_or(Fault::Overflow)?;
                }
            }
            let current = packet.as_mut().ok_or(Fault::NotReady)?;
            let length = (bytes.len() - at).min(current.bytes - current.offset);
            if current.silent {
                bytes[at..at + length].fill(0);
            } else {
                // SAFETY: GetBuffer holds this exact native packet until release.
                // Validated frame extents and the private cursor bound this copy;
                // caller-owned output cannot alias the private engine buffer.
                unsafe {
                    ptr::copy_nonoverlapping(
                        current.pointer.add(current.offset),
                        bytes[at..].as_mut_ptr(),
                        length,
                    )
                };
            }
            current.offset += length;
            at += length;
            if current.offset == current.bytes {
                let current = packet.take().ok_or(Fault::NotReady)?;
                // SAFETY: the exact original loan was completely consumed once.
                check("IAudioCaptureClient::ReleaseBuffer", unsafe {
                    (client.table().release)(client.raw(), current.frames)
                })?;
            }
        }
        Ok(())
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !bytes.len().is_multiple_of(self.frame_bytes) {
            return Err(Fault::InvalidInput.into());
        }
        if !matches!(self.stream, Stream::Render(_)) {
            return Err(Fault::InvalidInput.into());
        }
        let mut at = 0;
        while at < bytes.len() {
            let padding = self.padding()?;
            let available = self.frames.checked_sub(padding).ok_or(Fault::Malformed)?;
            if available == 0 {
                wait(&self.event)?;
                continue;
            }
            let frames = ((bytes.len() - at) / self.frame_bytes).min(available as usize) as u32;
            let length = frames as usize * self.frame_bytes;
            let Stream::Render(client) = &self.stream else {
                return Err(Fault::InvalidInput.into());
            };
            let mut data = ptr::null_mut();
            // SAFETY: request fits the actual current original engine capacity.
            check("IAudioRenderClient::GetBuffer", unsafe {
                (client.table().get)(client.raw(), frames, &mut data)
            })?;
            if data.is_null() {
                // SAFETY: release the original successful loan as silence before
                // refusing the malformed provider pointer; never dereference it.
                let cleanup = check("IAudioRenderClient::ReleaseBuffer(silence)", unsafe {
                    (client.table().release)(
                        client.raw(),
                        frames,
                        AUDCLNT_BUFFERFLAGS_SILENT as u32,
                    )
                });
                let original = Fault::Malformed.into();
                return Err(match cleanup {
                    Ok(()) => original,
                    Err(cleanup) => Error::Cleanup {
                        original: Box::new(original),
                        cleanup: Box::new(cleanup),
                    },
                });
            }
            // SAFETY: native writable loan holds exactly these requested frames;
            // the bounded borrowed input is independent and remains live.
            unsafe { ptr::copy_nonoverlapping(bytes[at..].as_ptr(), data, length) };
            // SAFETY: submit this original filled buffer once; a failed release
            // is returned, not retried or relabelled as a successful submission.
            check("IAudioRenderClient::ReleaseBuffer", unsafe {
                (client.table().release)(client.raw(), frames, 0)
            })?;
            at += length;
            self.start()?;
        }
        Ok(())
    }
    fn padding(&self) -> Result<u32, Error> {
        let mut padding = 0;
        // SAFETY: initialized original engine and exclusive scalar output.
        check("IAudioClient::GetCurrentPadding", unsafe {
            (self.engine.table().padding)(self.engine.raw(), &mut padding)
        })?;
        if padding > self.frames {
            return Err(Fault::Malformed.into());
        }
        Ok(padding)
    }
    pub(crate) fn take_discontinuities(&mut self) -> u64 {
        match &mut self.stream {
            Stream::Capture {
                discontinuities, ..
            } => std::mem::take(discontinuities),
            Stream::Render(_) => 0,
        }
    }
    fn release_packet(&mut self) -> Result<(), Error> {
        if let Stream::Capture { client, packet, .. } = &mut self.stream
            && packet.take().is_some()
        {
            // SAFETY: returning the original outstanding loan without claiming
            // its unconsumed tail. Stop/Reset below discards that native tail.
            check("IAudioCaptureClient::ReleaseBuffer(abandon)", unsafe {
                (client.table().release)(client.raw(), 0)
            })?;
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self, action: Finish) -> Result<(), Error> {
        let drain = action == Finish::Drain;
        if drain && matches!(self.stream, Stream::Render(_)) {
            while self.started && self.padding()? != 0 {
                wait(&self.event)?;
            }
        }
        self.release_packet()?;
        if self.started {
            // SAFETY: stop only this original initialized engine, before reset/release.
            check("IAudioClient::Stop", unsafe {
                (self.engine.table().stop)(self.engine.raw())
            })?;
            self.started = false;
        }
        if !drain {
            // SAFETY: stream is stopped and all original capture loans are returned.
            check("IAudioClient::Reset", unsafe {
                (self.engine.table().reset)(self.engine.raw())
            })?;
        }
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _packet = self.release_packet();
        if self.started {
            // SAFETY: best-effort stop of the original client before its final
            // COM references and event disappear; no successful drain is claimed.
            let _stop = unsafe { (self.engine.table().stop)(self.engine.raw()) };
        }
    }
}
