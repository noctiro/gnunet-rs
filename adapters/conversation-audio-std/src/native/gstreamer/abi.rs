//! GStreamer 1.x core/app APIs and the public message prefix.
use crate::{Error, native::library::Library};
use std::{
    ffi::{c_char, c_int, c_void},
    rc::Rc,
};

pub(super) type Ptr = *mut c_void;
pub(super) type Unref = unsafe extern "C" fn(Ptr);
type Init = unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char, *mut *mut GlibError) -> c_int;
type Parse = unsafe extern "C" fn(*const c_char, *mut *mut GlibError) -> Ptr;
type Ref = unsafe extern "C" fn(Ptr) -> Ptr;
type NamedRef = unsafe extern "C" fn(Ptr, *const c_char) -> Ptr;
type Name = unsafe extern "C" fn(Ptr) -> *mut c_char;
type Metadata = unsafe extern "C" fn(Ptr, *const c_char) -> *const c_char;
type State = unsafe extern "C" fn(Ptr, c_int) -> c_int;
type GetState = unsafe extern "C" fn(Ptr, *mut c_int, *mut c_int, u64) -> c_int;
type Bus = unsafe extern "C" fn(Ptr, u64, u32) -> Ptr;
type ParseError = unsafe extern "C" fn(Ptr, *mut *mut GlibError, *mut *mut c_char);
type FreeError = unsafe extern "C" fn(*mut GlibError);
type Allocate = unsafe extern "C" fn(Ptr, usize, Ptr) -> Ptr;
type Size = unsafe extern "C" fn(Ptr) -> usize;
type Flags = unsafe extern "C" fn(Ptr) -> u32;
type Fill = unsafe extern "C" fn(Ptr, usize, *const c_void, usize) -> usize;
type Extract = unsafe extern "C" fn(Ptr, usize, Ptr, usize) -> usize;
type Pull = unsafe extern "C" fn(Ptr, u64) -> Ptr;
type Control = unsafe extern "C" fn(Ptr) -> c_int;
type Push = unsafe extern "C" fn(Ptr, Ptr) -> c_int;
type Level = unsafe extern "C" fn(Ptr) -> u64;

#[repr(C)]
pub(super) struct GlibError {
    pub(super) domain: u32,
    pub(super) code: c_int,
    message: *mut c_char,
}

// The public macros GST_MESSAGE_TYPE and GST_MINI_OBJECT_CAST use this prefix.
#[repr(C)]
struct MiniObject {
    gtype: usize,
    refcount: c_int,
    lockstate: c_int,
    flags: u32,
    copy: Ptr,
    dispose: Ptr,
    free: Ptr,
    private_uint: u32,
    private_pointer: Ptr,
}

#[repr(C)]
pub(super) struct Message {
    mini: MiniObject,
    pub(super) kind: u32,
}

pub(super) struct Api {
    _core: Rc<Library>,
    _app: Rc<Library>,
    _glib: Rc<Library>,
    pub(super) init: Init,
    pub(super) parse: Parse,
    pub(super) object_unref: Unref,
    pub(super) object_name: Name,
    pub(super) mini_unref: Unref,
    pub(super) get_bus: Ref,
    pub(super) bin_element: NamedRef,
    pub(super) static_pad: NamedRef,
    pub(super) ghost_target: Ref,
    pub(super) pad_element: Ref,
    pub(super) element_factory: Ref,
    pub(super) factory_metadata: Metadata,
    pub(super) set_state: State,
    pub(super) get_state: GetState,
    pub(super) bus_message: Bus,
    pub(super) parse_error: ParseError,
    pub(super) free_error: FreeError,
    pub(super) free_memory: Unref,
    pub(super) allocate: Allocate,
    pub(super) size: Size,
    pub(super) flags: Flags,
    pub(super) fill: Fill,
    pub(super) extract: Extract,
    pub(super) sample_buffer: Ref,
    pub(super) pull: Pull,
    pub(super) sink_eos: Control,
    pub(super) push: Push,
    pub(super) end_source: Control,
    pub(super) queued: Level,
}

impl Api {
    pub(super) fn load() -> Result<Rc<Self>, Error> {
        #[cfg(target_os = "macos")]
        let (core_names, app_names, glib_names) = (
            [
                c"libgstreamer-1.0.0.dylib",
                c"/Library/Frameworks/GStreamer.framework/Versions/1.0/lib/libgstreamer-1.0.0.dylib",
            ],
            [
                c"libgstapp-1.0.0.dylib",
                c"/Library/Frameworks/GStreamer.framework/Versions/1.0/lib/libgstapp-1.0.0.dylib",
            ],
            [
                c"libglib-2.0.0.dylib",
                c"/Library/Frameworks/GStreamer.framework/Versions/1.0/lib/libglib-2.0.0.dylib",
            ],
        );
        #[cfg(not(target_os = "macos"))]
        let (core_names, app_names, glib_names) = (
            [c"libgstreamer-1.0.so.0", c"libgstreamer-1.0.so"],
            [c"libgstapp-1.0.so.0", c"libgstapp-1.0.so"],
            [c"libglib-2.0.so.0", c"libglib-2.0.so"],
        );
        let core = Library::open_resident(&core_names, "open GStreamer core")?;
        let app = Library::open_resident(&app_names, "open GStreamer app")?;
        let glib = Library::open_resident(&glib_names, "open GLib")?;
        macro_rules! bind {
            ($lib:ident, $symbol:literal, $abi:ty) => {
                std::mem::transmute::<Ptr, $abi>(
                    $lib.symbol($symbol, $symbol.to_str().unwrap_or("GStreamer symbol"))?,
                )
            };
        }
        // SAFETY: Every fixed name is bound with its public 1.x C signature.
        // These original loader references remain held by all native owners.
        let api = unsafe {
            Self {
                init: bind!(core, c"gst_init_check", Init),
                parse: bind!(core, c"gst_parse_launch", Parse),
                object_unref: bind!(core, c"gst_object_unref", Unref),
                object_name: bind!(core, c"gst_object_get_name", Name),
                mini_unref: bind!(core, c"gst_mini_object_unref", Unref),
                get_bus: bind!(core, c"gst_element_get_bus", Ref),
                bin_element: bind!(core, c"gst_bin_get_by_name", NamedRef),
                static_pad: bind!(core, c"gst_element_get_static_pad", NamedRef),
                ghost_target: bind!(core, c"gst_ghost_pad_get_target", Ref),
                pad_element: bind!(core, c"gst_pad_get_parent_element", Ref),
                element_factory: bind!(core, c"gst_element_get_factory", Ref),
                factory_metadata: bind!(core, c"gst_element_factory_get_metadata", Metadata),
                set_state: bind!(core, c"gst_element_set_state", State),
                get_state: bind!(core, c"gst_element_get_state", GetState),
                bus_message: bind!(core, c"gst_bus_timed_pop_filtered", Bus),
                parse_error: bind!(core, c"gst_message_parse_error", ParseError),
                free_error: bind!(glib, c"g_error_free", FreeError),
                free_memory: bind!(glib, c"g_free", Unref),
                allocate: bind!(core, c"gst_buffer_new_allocate", Allocate),
                size: bind!(core, c"gst_buffer_get_size", Size),
                flags: bind!(core, c"gst_buffer_get_flags", Flags),
                fill: bind!(core, c"gst_buffer_fill", Fill),
                extract: bind!(core, c"gst_buffer_extract", Extract),
                sample_buffer: bind!(core, c"gst_sample_get_buffer", Ref),
                pull: bind!(app, c"gst_app_sink_try_pull_sample", Pull),
                sink_eos: bind!(app, c"gst_app_sink_is_eos", Control),
                push: bind!(app, c"gst_app_src_push_buffer", Push),
                end_source: bind!(app, c"gst_app_src_end_of_stream", Control),
                queued: bind!(app, c"gst_app_src_get_current_level_bytes", Level),
                _core: core,
                _app: app,
                _glib: glib,
            }
        };
        Ok(Rc::new(api))
    }
}
