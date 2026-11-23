//! Original pipeline, app endpoint and bus references.
use super::{Direction, WAIT_LIMIT, abi};
use crate::{Error, error::retain_cleanup};
use gnunet_types::Error as Fault;
use std::{
    ffi::{CStr, CString},
    ptr::{self, NonNull},
    rc::Rc,
    time::Duration,
};

const STATE_NULL: i32 = 1;
const STATE_READY: i32 = 2;
const STATE_PLAYING: i32 = 4;
const STATE_FAILURE: i32 = 0;
const MESSAGE_EOS: u32 = 1;
const MESSAGE_ERROR: u32 = 1 << 1;

pub(super) struct Owned {
    raw: Option<NonNull<std::ffi::c_void>>,
    release: abi::Unref,
    _api: Rc<abi::Api>,
}

impl Owned {
    fn object(api: &Rc<abi::Api>, raw: abi::Ptr) -> Option<Self> {
        Self::adopt(api, raw, api.object_unref)
    }

    pub(super) fn mini(api: &Rc<abi::Api>, raw: abi::Ptr) -> Option<Self> {
        Self::adopt(api, raw, api.mini_unref)
    }

    fn adopt(api: &Rc<abi::Api>, raw: abi::Ptr, release: abi::Unref) -> Option<Self> {
        Some(Self {
            raw: Some(NonNull::new(raw)?),
            release,
            _api: Rc::clone(api),
        })
    }

    pub(super) fn as_ptr(&self) -> abi::Ptr {
        self.raw.map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    pub(super) fn into_raw(mut self) -> abi::Ptr {
        self.raw.take().map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(raw) = self.raw {
            // SAFETY: The original ref of the qualified object is still owned.
            unsafe { (self.release)(raw.as_ptr()) };
        }
    }
}

fn glib_error(
    api: &abi::Api,
    error: *mut abi::GlibError,
    operation: &'static str,
) -> Option<Error> {
    let error = NonNull::new(error)?;
    // SAFETY: The native call supplied one complete transferred GError or NULL.
    // Its numeric fields are copied before releasing exactly that reference.
    unsafe {
        let domain = (*error.as_ptr()).domain;
        let code = (*error.as_ptr()).code;
        (api.free_error)(error.as_ptr());
        Some(Error::Gstreamer {
            operation,
            domain,
            code,
        })
    }
}

fn native_refusal(operation: &'static str, code: i32) -> Error {
    Error::Provider {
        provider: "GStreamer",
        operation,
        code,
    }
}

pub(super) enum Event {
    Waiting,
    End,
}

pub(super) struct Pipeline {
    pub(super) api: Rc<abi::Api>,
    pub(super) endpoint: Owned,
    bus: Owned,
    pipeline: Owned,
    started: bool,
}

impl Pipeline {
    pub(super) fn open(direction: Direction, description: &CString) -> Result<Self, Error> {
        let api = abi::Api::load()?;
        let mut error = ptr::null_mut();
        // SAFETY: No arguments are passed. The non-null writable error output is
        // initially NULL as required. GStreamer owns its process initialization.
        let ok = unsafe { (api.init)(ptr::null_mut(), ptr::null_mut(), &mut error) };
        if let Some(error) = glib_error(&api, error, "initialization") {
            return Err(error);
        }
        if ok == 0 {
            return Err(native_refusal("initialization", ok));
        }
        // SAFETY: The original description is a fixed NUL-terminated pipeline
        // specification in Rust and the writable error output starts NULL.
        let raw = unsafe { (api.parse)(description.as_ptr(), &mut error) };
        let pipeline = Owned::object(&api, raw);
        if let Some(error) = glib_error(&api, error, "parse pipeline") {
            return Err(error);
        }
        let pipeline = pipeline.ok_or(Fault::Unavailable)?;
        // SAFETY: The description always forms a multi-element pipeline with a
        // named original app endpoint. Both calls transfer one new reference.
        let (bus, endpoint) = unsafe {
            (
                (api.get_bus)(pipeline.as_ptr()),
                (api.bin_element)(pipeline.as_ptr(), c"gnunet_pcm".as_ptr()),
            )
        };
        let bus = Owned::object(&api, bus);
        let endpoint = Owned::object(&api, endpoint);
        let mut product = Self {
            api,
            endpoint: endpoint.ok_or(Fault::Unavailable)?,
            bus: bus.ok_or(Fault::Unavailable)?,
            pipeline,
            started: true,
        };
        let started = product
            .transition(STATE_READY, "prepare device")
            .and_then(|()| product.require_audio_device(direction))
            .and_then(|()| product.transition(STATE_PLAYING, "start pipeline"));
        if let Err(error) = started {
            retain_cleanup(Err::<(), _>(error), product.stop())?;
        }
        Ok(product)
    }

    fn require_audio_device(&self, direction: Direction) -> Result<(), Error> {
        let api = &self.api;
        let mut state = 0;
        // SAFETY: One live pipeline and writable state output. READY selects the
        // auto bin's original hardware before inspecting its ghost-pad target.
        let observed = unsafe {
            (api.get_state)(
                self.pipeline.as_ptr(),
                &mut state,
                ptr::null_mut(),
                nanos(WAIT_LIMIT),
            )
        };
        if observed == STATE_FAILURE {
            return Err(self.failure("prepare device", observed));
        }
        if state != STATE_READY {
            return Err(Fault::Deadline.into());
        }
        let pad_name = match direction {
            Direction::Capture => c"src",
            Direction::Playback => c"sink",
        };
        // SAFETY: The fixed pipeline names the GStreamer automatic device bin.
        // Its public src/sink pad is a ghost pad. Each acquired ref is adopted
        // before the subsequent use, and the device element holds its factory.
        unsafe {
            let bin = Owned::object(
                api,
                (api.bin_element)(self.pipeline.as_ptr(), c"gnunet_device".as_ptr()),
            )
            .ok_or(Fault::Unavailable)?;
            let pad = Owned::object(api, (api.static_pad)(bin.as_ptr(), pad_name.as_ptr()))
                .ok_or(Fault::Unavailable)?;
            let target =
                Owned::object(api, (api.ghost_target)(pad.as_ptr())).ok_or(Fault::Unavailable)?;
            let selected =
                Owned::object(api, (api.pad_element)(target.as_ptr())).ok_or(Fault::Unavailable)?;
            let factory =
                NonNull::new((api.element_factory)(selected.as_ptr())).ok_or(Fault::Unavailable)?;
            let klass = NonNull::new(
                (api.factory_metadata)(factory.as_ptr(), c"klass".as_ptr()).cast_mut(),
            )
            .ok_or(Fault::Unavailable)?;
            let name =
                NonNull::new((api.object_name)(factory.as_ptr())).ok_or(Fault::Unavailable)?;
            let synthetic = matches!(
                CStr::from_ptr(name.as_ptr()).to_bytes(),
                b"fakesrc" | b"fakesink" | b"fakeaudiosink" | b"fakeaudiosrc" | b"audiotestsrc"
            );
            (api.free_memory)(name.as_ptr().cast());
            if !synthetic
                && CStr::from_ptr(klass.as_ptr())
                    .to_bytes()
                    .split(|byte| *byte == b'/')
                    .any(|part| part == b"Audio")
            {
                Ok(())
            } else {
                // An auto bin can substitute the generic fakesrc/fakesink.
                // Those factories have no Audio class or physical endpoint.
                Err(Fault::Unavailable.into())
            }
        }
    }

    fn transition(&self, state: i32, operation: &'static str) -> Result<(), Error> {
        // SAFETY: Only a valid native GstState is passed to the live pipeline.
        let result = unsafe { (self.api.set_state)(self.pipeline.as_ptr(), state) };
        if result == STATE_FAILURE {
            Err(self.failure(operation, result))
        } else {
            Ok(())
        }
    }

    pub(super) fn event(&self, wait: Duration) -> Result<Event, Error> {
        // SAFETY: Borrowed bus is live, gives one owned message or NULL, and the
        // filter accepts only the two handled GstMessageType flags.
        let raw = unsafe {
            (self.api.bus_message)(self.bus.as_ptr(), nanos(wait), MESSAGE_EOS | MESSAGE_ERROR)
        };
        let Some(message) = Owned::mini(&self.api, raw) else {
            return Ok(Event::Waiting);
        };
        // SAFETY: The retained message begins with the public GStreamer 1.x
        // GstMessage prefix. GStreamer does not mutate the message kind.
        let kind = unsafe { (*message.as_ptr().cast::<abi::Message>()).kind };
        match kind {
            MESSAGE_EOS => Ok(Event::End),
            MESSAGE_ERROR => {
                let mut error = ptr::null_mut();
                // SAFETY: Verified error message. Only the writable GError
                // output is requested, with no ownership for debug text.
                unsafe {
                    (self.api.parse_error)(message.as_ptr(), &mut error, ptr::null_mut());
                }
                Err(glib_error(&self.api, error, "pipeline").unwrap_or_else(|| Fault::Io.into()))
            }
            _ => Err(Fault::Malformed.into()),
        }
    }

    pub(super) fn require_live(&self) -> Result<(), Error> {
        match self.event(Duration::ZERO)? {
            Event::Waiting => Ok(()),
            Event::End => Err(Fault::Closed.into()),
        }
    }

    pub(super) fn failure(&self, operation: &'static str, code: i32) -> Error {
        self.event(Duration::ZERO)
            .err()
            .unwrap_or_else(|| native_refusal(operation, code))
    }

    pub(super) fn stop(&mut self) -> Result<(), Error> {
        if !std::mem::take(&mut self.started) {
            return Ok(());
        }
        self.transition(STATE_NULL, "stop pipeline")
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        drop(self.stop());
    }
}

pub(super) fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX - 1)
}
