//! Only the standard POSIX loader, libopus and PulseAudio simple ABI boundary.
//! No GNUnet library/helper implements protocol/media work for this Rust owner.
use crate::{DECODE_SAMPLES, Error, Limits, RATE, RECORD_SAMPLES};
use gnunet_types::Error as Fault;
use libc::{c_char, c_int, c_void};
use std::{ffi::CStr, ptr::NonNull, rc::Rc};
#[cfg(any(target_os = "linux", target_os = "android"))]
#[link(name = "dl")]
unsafe extern "C" {}
struct Library {
    handle: NonNull<c_void>,
}
fn loader_diagnostic(operation: &'static str, raw: *const c_char) -> Error {
    // SAFETY: POSIX dlerror returns NULL or a valid NUL-terminated diagnostic
    // until the next loader call. It is copied immediately, before any such call.
    if raw.is_null() {
        return Error::Loader {
            operation,
            detail: "native loader returned a null symbol/handle without a diagnostic".into(),
            truncated: false,
        };
    }
    // SAFETY: The non-null pointer above is the current loader's valid string.
    let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
    let n = bytes.len().min(1024);
    let mut detail = String::new();
    if detail.try_reserve_exact(n * 4).is_err() {
        return Fault::Capacity.into();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in &bytes[..n] {
        if b.is_ascii_graphic() || *b == b' ' {
            detail.push(char::from(*b));
        } else {
            detail.push('\\');
            detail.push('x');
            detail.push(char::from(HEX[usize::from(*b >> 4)]));
            detail.push(char::from(HEX[usize::from(*b & 15)]));
        }
    }
    Error::Loader {
        operation,
        detail,
        truncated: bytes.len() > n,
    }
}
impl Library {
    fn open(names: &[&CStr], operation: &'static str) -> Result<Rc<Self>, Error> {
        let mut failure = None;
        for name in names {
            // SAFETY: Each fixed library name is NUL-terminated. NOW/LOCAL are
            // standard loader flags; no symbol is called until its ABI is bound.
            let raw = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if let Some(handle) = NonNull::new(raw) {
                return Ok(Rc::new(Self { handle }));
            }
            // SAFETY: Fetch the actual current failed dlopen diagnostic immediately.
            let error = unsafe { libc::dlerror() };
            failure = Some(loader_diagnostic(operation, error));
        }
        Err(failure.unwrap_or_else(|| Fault::Unavailable.into()))
    }
    fn symbol(&self, name: &CStr, operation: &'static str) -> Result<*mut c_void, Error> {
        // SAFETY: The original owned handle is live, and name is NUL-terminated.
        // Clearing/checking dlerror distinguishes lookup failure from null data.
        let (symbol, error) = unsafe {
            let _old = libc::dlerror();
            let p = libc::dlsym(self.handle.as_ptr(), name.as_ptr());
            (p, libc::dlerror())
        };
        if !error.is_null() || symbol.is_null() {
            return Err(loader_diagnostic(operation, error));
        }
        Ok(symbol)
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: This is the final Rc owner after all codec/device handles using
        // these symbols were destroyed. No dangling function pointer is invoked.
        let _status = unsafe { libc::dlclose(self.handle.as_ptr()) };
    }
}
type Size = unsafe extern "C" fn(c_int) -> c_int;
type EncoderCreate = unsafe extern "C" fn(i32, c_int, c_int, *mut c_int) -> *mut c_void;
type DecoderCreate = unsafe extern "C" fn(i32, c_int, *mut c_int) -> *mut c_void;
type Destroy = unsafe extern "C" fn(*mut c_void);
type Encode = unsafe extern "C" fn(*mut c_void, *const f32, c_int, *mut u8, i32) -> i32;
type Decode = unsafe extern "C" fn(*mut c_void, *const u8, i32, *mut f32, c_int, c_int) -> c_int;
type Ctl = unsafe extern "C" fn(*mut c_void, c_int, ...) -> c_int;
type Samples = unsafe extern "C" fn(*const u8, i32, i32) -> c_int;
struct OpusApi {
    _library: Rc<Library>,
    encoder_size: Size,
    decoder_size: Size,
    encoder_create: EncoderCreate,
    decoder_create: DecoderCreate,
    encoder_destroy: Destroy,
    decoder_destroy: Destroy,
    encode: Encode,
    decode: Decode,
    encoder_ctl: Ctl,
    decoder_ctl: Ctl,
    samples: Samples,
}
impl OpusApi {
    fn load() -> Result<Rc<Self>, Error> {
        #[cfg(target_os = "macos")]
        let names = [c"libopus.0.dylib", c"libopus.dylib"];
        #[cfg(not(target_os = "macos"))]
        let names = [c"libopus.so.0", c"libopus.so"];
        let l = Library::open(&names, "open libopus")?;
        // SAFETY: These exact exported standard libopus names have the public
        // signatures declared above. POSIX dlsym function addresses may be cast
        // to those signatures; the Rc library outlives every state and call.
        let api = unsafe {
            Self {
                encoder_size: std::mem::transmute::<*mut c_void, Size>(
                    l.symbol(c"opus_encoder_get_size", "opus_encoder_get_size")?,
                ),
                decoder_size: std::mem::transmute::<*mut c_void, Size>(
                    l.symbol(c"opus_decoder_get_size", "opus_decoder_get_size")?,
                ),
                encoder_create: std::mem::transmute::<*mut c_void, EncoderCreate>(
                    l.symbol(c"opus_encoder_create", "opus_encoder_create")?,
                ),
                decoder_create: std::mem::transmute::<*mut c_void, DecoderCreate>(
                    l.symbol(c"opus_decoder_create", "opus_decoder_create")?,
                ),
                encoder_destroy: std::mem::transmute::<*mut c_void, Destroy>(
                    l.symbol(c"opus_encoder_destroy", "opus_encoder_destroy")?,
                ),
                decoder_destroy: std::mem::transmute::<*mut c_void, Destroy>(
                    l.symbol(c"opus_decoder_destroy", "opus_decoder_destroy")?,
                ),
                encode: std::mem::transmute::<*mut c_void, Encode>(
                    l.symbol(c"opus_encode_float", "opus_encode_float")?,
                ),
                decode: std::mem::transmute::<*mut c_void, Decode>(
                    l.symbol(c"opus_decode_float", "opus_decode_float")?,
                ),
                encoder_ctl: std::mem::transmute::<*mut c_void, Ctl>(
                    l.symbol(c"opus_encoder_ctl", "opus_encoder_ctl")?,
                ),
                decoder_ctl: std::mem::transmute::<*mut c_void, Ctl>(
                    l.symbol(c"opus_decoder_ctl", "opus_decoder_ctl")?,
                ),
                samples: std::mem::transmute::<*mut c_void, Samples>(
                    l.symbol(c"opus_packet_get_nb_samples", "opus_packet_get_nb_samples")?,
                ),
                _library: l,
            }
        };
        Ok(Rc::new(api))
    }
}
fn opus(operation: &'static str, code: i32) -> Error {
    Error::Provider {
        provider: "Opus",
        operation,
        code,
    }
}
/// One actual mono48k40ms VOIP encoder, no private PCM fallback.
pub(crate) struct Encoder {
    api: Rc<OpusApi>,
    state: NonNull<c_void>,
}
impl Encoder {
    pub(crate) fn new(limits: Limits) -> Result<Self, Error> {
        let api = OpusApi::load()?;
        // SAFETY: The bound API query accepts channel count1 and touches no state.
        let bytes = unsafe { (api.encoder_size)(1) };
        if bytes <= 0 {
            return Err(opus("encoder_get_size", bytes));
        }
        if usize::try_from(bytes).map_err(|_| Fault::Overflow)? > limits.codec_state_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut error = 0;
        // SAFETY: All scalar parameters are supported by Opus. The mutable error
        // pointer is valid; a successful result is owned until the real destroy.
        let raw = unsafe { (api.encoder_create)(48000, 1, 2048, &mut error) };
        let state = NonNull::new(raw).ok_or_else(|| opus("encoder_create", error))?;
        let mut encoder = Self { api, state };
        if error != 0 {
            return Err(opus("encoder_create", error));
        }
        for (request, value) in [(4014, 1), (4010, 10), (4012, 1), (4024, 3001)] {
            encoder.control(request, value)?;
        }
        Ok(encoder)
    }
    fn control(&mut self, request: c_int, value: c_int) -> Result<(), Error> {
        // SAFETY: The live original encoder and the four documented integer
        // SET controls above use exactly one promoted C int variadic argument.
        let result = unsafe { (self.api.encoder_ctl)(self.state.as_ptr(), request, value) };
        if result != 0 {
            return Err(opus("encoder_ctl", result));
        }
        Ok(())
    }
    pub(crate) fn encode(&mut self, pcm: &[f32], output: &mut [u8]) -> Result<usize, Error> {
        if pcm.len() != RECORD_SAMPLES || output.len() != 1024 || pcm.iter().any(|v| !v.is_finite())
        {
            return Err(Fault::InvalidInput.into());
        }
        // SAFETY: The encoder is mono;1920 samples and1024 writable output
        // bytes match the validated slices. The library retains neither pointer.
        let result = unsafe {
            (self.api.encode)(
                self.state.as_ptr(),
                pcm.as_ptr(),
                1920,
                output.as_mut_ptr(),
                1024,
            )
        };
        if result <= 0 {
            return Err(opus("encode_float", result));
        }
        let n = usize::try_from(result).map_err(|_| Fault::Overflow)?;
        if n > output.len() {
            return Err(Fault::Malformed.into());
        }
        Ok(n)
    }
}
impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: This original non-null state was created by this still-live API
        // and has not been freed or shared. Native destroy is its matching owner.
        unsafe { (self.api.encoder_destroy)(self.state.as_ptr()) };
    }
}
/// Actual mono/stereo48k mapping0 decoder and public packet duration query.
pub(crate) struct Decoder {
    api: Rc<OpusApi>,
    state: NonNull<c_void>,
    channels: usize,
    gain: f32,
}
impl Decoder {
    pub(crate) fn new(channels: u8, gain: i16, limits: Limits) -> Result<Self, Error> {
        if !(1..=2).contains(&channels) {
            return Err(Fault::Unsupported.into());
        }
        let api = OpusApi::load()?;
        // SAFETY: Query is independent of state and supports channel counts1/2.
        let size = unsafe { (api.decoder_size)(c_int::from(channels)) };
        if size <= 0 {
            return Err(opus("decoder_get_size", size));
        }
        if usize::try_from(size).map_err(|_| Fault::Overflow)? > limits.codec_state_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut error = 0;
        // SAFETY: Valid48k rate/channel count, writable error pointer; the actual
        // successful state is retained under the matching library/destroy owner.
        let raw = unsafe { (api.decoder_create)(48000, c_int::from(channels), &mut error) };
        let state = NonNull::new(raw).ok_or_else(|| opus("decoder_create", error))?;
        let mut decoder = Self {
            api,
            state,
            channels: usize::from(channels),
            gain: 1.0,
        };
        if error != 0 {
            return Err(opus("decoder_create", error));
        }
        if gain != 0 {
            // SAFETY: OPUS_SET_GAIN_REQUEST4034 accepts one promoted signed C
            // int in Q8dB; gain is the real signed little-endian header field.
            let result = unsafe {
                (decoder.api.decoder_ctl)(decoder.state.as_ptr(), 4034, c_int::from(gain))
            };
            if result == -5 {
                decoder.gain = 10.0f32.powf(f32::from(gain) / 5120.0);
            } else if result != 0 {
                return Err(opus("decoder gain", result));
            }
        }
        Ok(decoder)
    }
    pub(crate) fn samples(&self, packet: &[u8]) -> Result<usize, Error> {
        let len = i32::try_from(packet.len()).map_err(|_| Fault::TooLarge)?;
        // SAFETY: The packet borrow is valid for its full checked length, and
        // the public query retains no pointer or state and receives rate48000.
        let result = unsafe { (self.api.samples)(packet.as_ptr(), len, 48000) };
        if result <= 0 || result > 5760 {
            return Err(opus("packet duration", result));
        }
        usize::try_from(result).map_err(|_| Fault::Overflow.into())
    }
    pub(crate) fn decode(&mut self, packet: &[u8], pcm: &mut [f32]) -> Result<usize, Error> {
        if pcm.len() < DECODE_SAMPLES * self.channels {
            return Err(Fault::Capacity.into());
        }
        let len = i32::try_from(packet.len()).map_err(|_| Fault::TooLarge)?;
        // SAFETY: The original decoder's validated channel count requires at
        // most5760*channels floats; output provides that extent, input is live,
        // and decode_fec0 decodes only the actual packet, never invented loss.
        let result = unsafe {
            (self.api.decode)(
                self.state.as_ptr(),
                packet.as_ptr(),
                len,
                pcm.as_mut_ptr(),
                5760,
                0,
            )
        };
        if result <= 0 || result > 5760 {
            return Err(opus("decode_float", result));
        }
        let n = usize::try_from(result).map_err(|_| Fault::Overflow)?;
        for sample in &mut pcm[..n * self.channels] {
            *sample *= self.gain;
            if !sample.is_finite() {
                return Err(Fault::Malformed.into());
            }
        }
        Ok(n)
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: This unique original decoder is live under the same retained API.
        unsafe { (self.api.decoder_destroy)(self.state.as_ptr()) };
    }
}
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
pub(crate) struct Pulse {
    api: Rc<PulseApi>,
    state: NonNull<c_void>,
    record: bool,
}
impl Pulse {
    pub(crate) fn new(record: bool, channels: u8) -> Result<Self, Error> {
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
    pub(crate) fn finish(&mut self, drain: bool) -> Result<(), Error> {
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
impl Drop for Pulse {
    fn drop(&mut self) {
        // SAFETY: The same original library frees its sole live stream before the
        // final library owner can be released. No native pointer remains callable.
        unsafe { (self.api.free)(self.state.as_ptr()) };
    }
}
