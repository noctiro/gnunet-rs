//! Stable libopus C ABI, independent of the native audio endpoint provider.
use super::library::Library;
use crate::{DECODE_SAMPLES, Error, Limits, RECORD_SAMPLES};
use gnunet_types::Error as Fault;
use std::{
    ffi::{c_int, c_void},
    ptr::NonNull,
    rc::Rc,
};
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
        #[cfg(all(unix, not(target_os = "macos")))]
        let names = [c"libopus.so.0", c"libopus.so"];
        #[cfg(windows)]
        let names = [c"libopus-0.dll", c"opus.dll"];
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
