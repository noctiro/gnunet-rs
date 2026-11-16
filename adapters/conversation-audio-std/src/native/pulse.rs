//! Standard PulseAudio simple stream and original device/library owners.
use super::library::Library;
use crate::{Error, RATE, RECORD_SAMPLES};
use gnunet_types::Error as Fault;
use std::{
    ffi::{c_char, c_int, c_void},
    ptr::NonNull,
    rc::Rc,
};
#[repr(C)]
struct SampleSpec {
    format: c_int,
    rate: u32,
    channels: u8,
}
#[repr(C)]
struct BufferAttr {
    maxlength: u32,
    tlength: u32,
    prebuf: u32,
    minreq: u32,
    fragsize: u32,
}
type PulseNew = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *const c_char,
    *const SampleSpec,
    *const c_void,
    *const BufferAttr,
    *mut c_int,
) -> *mut c_void;
type PulseFree = unsafe extern "C" fn(*mut c_void);
type PulseRead = unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *mut c_int) -> c_int;
type PulseWrite = unsafe extern "C" fn(*mut c_void, *const c_void, usize, *mut c_int) -> c_int;
type PulseControl = unsafe extern "C" fn(*mut c_void, *mut c_int) -> c_int;
struct PulseApi {
    _library: Rc<Library>,
    new: PulseNew,
    free: PulseFree,
    read: PulseRead,
    write: PulseWrite,
    drain: PulseControl,
    flush: PulseControl,
}
impl PulseApi {
    fn load() -> Result<Rc<Self>, Error> {
        #[cfg(target_os = "macos")]
        let names = [c"libpulse-simple.0.dylib", c"libpulse-simple.dylib"];
        #[cfg(not(target_os = "macos"))]
        let names = [c"libpulse-simple.so.0", c"libpulse-simple.so"];
        let l = Library::open(&names, "open PulseAudio simple")?;
        // SAFETY: Exact public PulseAudio simple ABI signatures. The original
        // POSIX library owner remains live until every using stream is freed.
        let api = unsafe {
            Self {
                new: std::mem::transmute::<*mut c_void, PulseNew>(
                    l.symbol(c"pa_simple_new", "pa_simple_new")?,
                ),
                free: std::mem::transmute::<*mut c_void, PulseFree>(
                    l.symbol(c"pa_simple_free", "pa_simple_free")?,
                ),
                read: std::mem::transmute::<*mut c_void, PulseRead>(
                    l.symbol(c"pa_simple_read", "pa_simple_read")?,
                ),
                write: std::mem::transmute::<*mut c_void, PulseWrite>(
                    l.symbol(c"pa_simple_write", "pa_simple_write")?,
                ),
                drain: std::mem::transmute::<*mut c_void, PulseControl>(
                    l.symbol(c"pa_simple_drain", "pa_simple_drain")?,
                ),
                flush: std::mem::transmute::<*mut c_void, PulseControl>(
                    l.symbol(c"pa_simple_flush", "pa_simple_flush")?,
                ),
                _library: l,
            }
        };
        Ok(Rc::new(api))
    }
}
/// One actual blocking PulseAudio simple stream, confined to its helper process.
pub(crate) struct Device {
    api: Rc<PulseApi>,
    state: NonNull<c_void>,
    record: bool,
}
impl Device {
    pub(crate) const fn take_discontinuities(&mut self) -> u64 {
        0
    }
    pub(crate) fn new(direction: super::Direction, channels: u8) -> Result<Self, Error> {
        let record = direction == super::Direction::Capture;
        if !(1..=2).contains(&channels) {
            return Err(Fault::Unsupported.into());
        }
        let api = PulseApi::load()?;
        let spec = SampleSpec {
            format: 5,
            rate: RATE,
            channels,
        };
        let quantum = RECORD_SAMPLES
            .checked_mul(usize::from(channels))
            .and_then(|n| n.checked_mul(4))
            .ok_or(Fault::Overflow)?;
        let quantum = u32::try_from(quantum).map_err(|_| Fault::Overflow)?;
        let attr = BufferAttr {
            maxlength: quantum.checked_mul(4).ok_or(Fault::Overflow)?,
            tlength: quantum.checked_mul(2).ok_or(Fault::Overflow)?,
            prebuf: quantum,
            minreq: quantum,
            fragsize: quantum,
        };
        let mut error = 0;
        // SAFETY: All strings are static C strings; nullable server/device/map
        // select the actual standard defaults. repr(C) sample/attribute values
        // match the public ABI and remain borrowed until this synchronous call
        // returns. The error pointer is live; direction is PLAYBACK1/RECORD2.
        let raw = unsafe {
            (api.new)(
                std::ptr::null(),
                c"GNUnet Conversation Rust".as_ptr(),
                if record { 2 } else { 1 },
                std::ptr::null(),
                if record {
                    c"GNUnet VoIP recorder".as_ptr()
                } else {
                    c"GNUnet VoIP playback".as_ptr()
                },
                &spec,
                std::ptr::null(),
                &attr,
                &mut error,
            )
        };
        let state = NonNull::new(raw).ok_or(Error::Provider {
            provider: "PulseAudio",
            operation: "simple_new",
            code: error,
        })?;
        Ok(Self { api, state, record })
    }
    pub(crate) fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if !self.record {
            return Err(Fault::InvalidInput.into());
        }
        let mut error = 0;
        // SAFETY: This is a live RECORD stream; the exact writable PCM slice is
        // borrowed until the blocking all-bytes read returns, never retained.
        let result = unsafe {
            (self.api.read)(
                self.state.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                &mut error,
            )
        };
        if result < 0 {
            return Err(Error::Provider {
                provider: "PulseAudio",
                operation: "simple_read",
                code: error,
            });
        }
        Ok(())
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.record {
            return Err(Fault::InvalidInput.into());
        }
        let mut error = 0;
        // SAFETY: This live PLAYBACK stream receives a valid exact PCM byte
        // borrow until the blocking all-bytes write returns; no pointer escapes.
        let result = unsafe {
            (self.api.write)(
                self.state.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                &mut error,
            )
        };
        if result < 0 {
            return Err(Error::Provider {
                provider: "PulseAudio",
                operation: "simple_write",
                code: error,
            });
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self, action: super::Finish) -> Result<(), Error> {
        let drain = action == super::Finish::Drain;
        let mut error = 0;
        // SAFETY: Both documented control functions take this live stream and
        // writable error integer only. Blocking is confined to this process.
        let result = unsafe {
            if drain {
                (self.api.drain)(self.state.as_ptr(), &mut error)
            } else {
                (self.api.flush)(self.state.as_ptr(), &mut error)
            }
        };
        if result < 0 {
            return Err(Error::Provider {
                provider: "PulseAudio",
                operation: if drain {
                    "simple_drain"
                } else {
                    "simple_flush"
                },
                code: error,
            });
        }
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: The same original library frees its sole live stream before the
        // final library owner can be released. No native pointer remains callable.
        unsafe { (self.api.free)(self.state.as_ptr()) };
    }
}
