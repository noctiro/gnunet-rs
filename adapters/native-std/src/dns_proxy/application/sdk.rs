//! AppKit's main-thread loop and the current containing bundle's bounded values.
use super::Identity;
use block2::RcBlock;
use objc2::{
    encode::{Encode, Encoding},
    msg_send,
    rc::{Retained, autoreleasepool},
    runtime::{AnyClass, AnyObject},
};
use objc2_foundation::{NSString, NSUTF8StringEncoding, ns_string};
use std::{
    cell::{Cell, RefCell},
    io,
    path::PathBuf,
    rc::Rc,
};

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    static NSApp: *mut AnyObject;
    static NSApplicationDidFinishLaunchingNotification: *const NSString;
}
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    static NSRunLoopCommonModes: *const NSString;
}

fn main_thread() -> io::Result<()> {
    // SAFETY: Darwin's main-thread predicate has no borrowed arguments.
    if unsafe { libc::pthread_main_np() } == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "containing application requires the main thread",
        ))
    } else {
        Ok(())
    }
}
fn class(name: &std::ffi::CStr) -> io::Result<&'static AnyClass> {
    AnyClass::get(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "native application class unavailable",
        )
    })
}
pub(super) fn identity() -> io::Result<Identity> {
    main_thread()?;
    autoreleasepool(|_| {
        // SAFETY: NSBundle's immutable main bundle is retained for every lookup.
        let bundle: Retained<AnyObject> = unsafe { msg_send![class(c"NSBundle")?, mainBundle] };
        let package = field(&bundle, ns_string!("CFBundlePackageType"), 4)?;
        if package != "APPL" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS management requires a containing APPL bundle",
            ));
        }
        let bundle_identifier = field(&bundle, ns_string!("CFBundleIdentifier"), 255)?;
        let provider_identifier = field(&bundle, ns_string!("GNUnetDNSProviderIdentifier"), 255)?;
        let provider_version = field(&bundle, ns_string!("GNUnetDNSProviderVersion"), 32)?;
        if !identifier(&bundle_identifier)
            || !identifier(&provider_identifier)
            || !provider_identifier.starts_with(&format!("{bundle_identifier}."))
            || provider_version.split('.').count() != 3
            || provider_version
                .split('.')
                .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid containing application provider identifiers or version",
            ));
        }
        // SAFETY: bundlePath returns the path of this retained NSBundle.
        let path: Retained<NSString> = unsafe { msg_send![&*bundle, bundlePath] };
        let bundle_path = PathBuf::from(text(&path, 4096)?);
        if !bundle_path.is_absolute() || bundle_path.extension().is_none_or(|ext| ext != "app") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS management requires an absolute containing .app path",
            ));
        }
        Ok(Identity {
            bundle_identifier,
            provider_identifier,
            provider_version,
            bundle_path,
        })
    })
}
fn identifier(value: &str) -> bool {
    value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn field(bundle: &AnyObject, key: &NSString, maximum: usize) -> io::Result<String> {
    // SAFETY: NSObject values are retained then checked before NSString access.
    let value: Option<Retained<AnyObject>> =
        unsafe { msg_send![bundle, objectForInfoDictionaryKey: key] };
    let string = value
        .and_then(|value| value.downcast::<NSString>().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing string in app metadata")
        })?;
    text(&string, maximum)
}
fn text(string: &NSString, maximum: usize) -> io::Result<String> {
    if string.length() > maximum {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
    let pointer = string.UTF8String();
    if length == 0 || length > maximum || pointer.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: NSString owns its checked immutable UTF-8 extent during this copy.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    let value = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    if value.contains('\0') {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(value.to_owned())
}

pub(super) struct Application(Retained<AnyObject>);
impl Application {
    pub fn new() -> io::Result<Self> {
        main_thread()?;
        // SAFETY: AppKit's main-thread global is read before this host creates
        // its unique application. A prior instance might already have posted
        // its one launch notification, so it cannot be adopted by this host.
        if unsafe { !NSApp.is_null() } {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "AppKit application is already initialized",
            ));
        }
        // SAFETY: NSApplication is initialized and used exclusively on main.
        let object: Retained<AnyObject> =
            unsafe { msg_send![class(c"NSApplication")?, sharedApplication] };
        // SAFETY: Exact NSApplication instance getters and regular GUI policy.
        let running: bool = unsafe { msg_send![&*object, isRunning] };
        if running {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "containing application event loop already running",
            ));
        }
        // SAFETY: NSApplicationActivationPolicyRegular is NSInteger value zero.
        let regular: bool = unsafe { msg_send![&*object, setActivationPolicy: 0_isize] };
        if !regular {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "regular containing application policy refused",
            ));
        }
        Ok(Self(object))
    }
    pub fn stopper(&self) -> io::Result<Stopper> {
        // SAFETY: Exact NSEvent constructor and SDK NSPoint layout. The event
        // is reserved before polling, so completion needs no event allocation.
        let event: Option<Retained<AnyObject>> = unsafe {
            msg_send![class(c"NSEvent")?,
                otherEventWithType: 15_usize,
                location: Point { x: 0.0, y: 0.0 },
                modifierFlags: 0_usize,
                timestamp: 0.0_f64,
                windowNumber: 0_isize,
                context: Option::<&AnyObject>::None,
                subtype: 0_i16,
                data1: 0_isize,
                data2: 0_isize
            ]
        };
        Ok(Stopper {
            application: self.0.clone(),
            event: event
                .ok_or_else(|| io::Error::other("application wake event allocation failed"))?,
        })
    }
    pub fn run(&self) {
        // SAFETY: This original main-thread NSApplication owns its standard run
        // lifecycle, including finishLaunching and native event dispatch.
        unsafe {
            let _: () = msg_send![&*self.0, run];
        }
    }
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Point {
    x: f64,
    y: f64,
}
// SAFETY: NSPoint is CGPoint on supported 64-bit macOS, with two CGFloat doubles.
unsafe impl Encode for Point {
    const ENCODING: Encoding = Encoding::Struct("CGPoint", &[Encoding::Double, Encoding::Double]);
}
#[derive(Clone)]
pub(super) struct Stopper {
    application: Retained<AnyObject>,
    event: Retained<AnyObject>,
}
impl Stopper {
    pub fn stop(&self) {
        // SAFETY: Both retained objects belong to this original main-thread
        // loop. stop: from a timer requires an actual event to unblock run.
        unsafe {
            let _: () = msg_send![&*self.application, stop: Option::<&AnyObject>::None];
            let _: () = msg_send![&*self.application, postEvent: &*self.event, atStart: true];
        }
    }
}
/// A retained exact-app launch observer and its subsequently created timer.
pub(super) struct Launch {
    center: Retained<AnyObject>,
    observer: Retained<AnyObject>,
    timer: Rc<RefCell<Option<Timer>>>,
}
impl Launch {
    pub fn new(
        application: &Application,
        tick: impl Fn() + 'static,
        failed: impl Fn(io::Error) + 'static,
    ) -> io::Result<Self> {
        main_thread()?;
        let timer = Rc::new(RefCell::new(None));
        let installed = Rc::clone(&timer);
        let observed = Cell::new(false);
        let tick = Rc::new(tick);
        let block = RcBlock::new(move |_notification: &AnyObject| {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if observed.replace(true) {
                    return;
                }
                let tick = Rc::clone(&tick);
                match Timer::new(move || tick()) {
                    Ok(timer) => {
                        *installed.borrow_mut() = Some(timer);
                    }
                    Err(error) => failed(error),
                }
            })) {
                super::super::completion::dispose_panic(payload);
                std::process::abort();
            }
        });
        // SAFETY: Registration precedes this unique application's run. AppKit
        // posts this exact-app notification on main after finishLaunching. A
        // nil queue preserves synchronous delivery on that posting thread.
        let (center, observer): (Retained<AnyObject>, Option<Retained<AnyObject>>) = unsafe {
            let center: Retained<AnyObject> =
                msg_send![class(c"NSNotificationCenter")?, defaultCenter];
            let observer = msg_send![&*center,
                addObserverForName: &*NSApplicationDidFinishLaunchingNotification,
                object: &*application.0,
                queue: Option::<&AnyObject>::None,
                usingBlock: &*block
            ];
            (center, observer)
        };
        Ok(Self {
            center,
            observer: observer
                .ok_or_else(|| io::Error::other("application launch observer allocation failed"))?,
            timer,
        })
    }
}
impl Drop for Launch {
    fn drop(&mut self) {
        // SAFETY: Remove only this original retained observer on its main
        // posting thread before releasing its captured driver or timer.
        unsafe {
            let _: () = msg_send![&*self.center, removeObserver: &*self.observer];
        }
        let timer = self.timer.borrow_mut().take();
        drop(timer);
    }
}
struct Timer(Retained<AnyObject>);
impl Timer {
    fn new(tick: impl Fn() + 'static) -> io::Result<Self> {
        main_thread()?;
        let block = RcBlock::new(move |_timer: &AnyObject| {
            // All Rust unwinding, including an unexpected reentrant borrow,
            // remains contained before returning through Foundation's block.
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tick();
            })) {
                super::super::completion::dispose_panic(payload);
                std::process::abort();
            }
        });
        // SAFETY: The private timer is installed only on this main run loop,
        // never exposed for cross-thread fire, and invalidated on the same thread.
        let timer: Retained<AnyObject> = unsafe {
            msg_send![class(c"NSTimer")?, timerWithTimeInterval: 0.025_f64, repeats: true, block: &*block]
        };
        // SAFETY: Main owns this run loop; common mode keeps bounded operation
        // polling active while the user interacts with native application UI.
        unsafe {
            let run_loop: Retained<AnyObject> = msg_send![class(c"NSRunLoop")?, currentRunLoop];
            let _: () = msg_send![&*run_loop, addTimer: &*timer, forMode: &*NSRunLoopCommonModes];
        }
        Ok(Self(timer))
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        // SAFETY: This unique private timer remains on its installing main thread.
        unsafe {
            let _: () = msg_send![&*self.0, invalidate];
        }
    }
}
