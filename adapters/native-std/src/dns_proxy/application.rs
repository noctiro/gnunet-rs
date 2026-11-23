//! Main-thread AppKit host for the containing application's original operations.
use std::{
    cell::{Cell, RefCell},
    io,
    path::PathBuf,
    rc::Rc,
    task::Poll,
};
#[expect(
    unsafe_code,
    reason = "Exact AppKit/Foundation selectors isolate main-thread application, bundle, timer and event ownership"
)]
mod sdk;

/// Bounded main-bundle declarations; signing and activation remain OS decisions.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The containing APPL bundle's CFBundleIdentifier.
    pub bundle_identifier: String,
    /// Original packaged GNUnetDNSProviderIdentifier, within the app identifier.
    pub provider_identifier: String,
    /// Original packaged GNUnetDNSProviderVersion.
    pub provider_version: String,
    /// Absolute path of the original containing application bundle.
    pub bundle_path: PathBuf,
}

/// Runs bounded management polling within a real AppKit application event loop.
#[derive(Debug)]
pub struct Application;
impl Application {
    /// Read the current containing application's declared identifiers and path.
    /// This does not construct a manager or grant signing/activation authority.
    /// # Errors
    /// Refuses a non-main caller, a non-APPL bundle or invalid/missing metadata.
    pub fn identity() -> io::Result<Identity> {
        sdk::identity()
    }

    /// Poll one original operation on the main thread while AppKit runs normally.
    /// The private common-mode timer polls at 25 ms intervals; it starts after
    /// AppKit finishes launching. Returning Pending neither cancels nor retries
    /// native work. The driver must keep every original pending owner itself.
    /// No system-extension activation or DNS configuration is performed here.
    /// # Errors
    /// Refuses invalid bundle/thread identity, an initialized AppKit app, unavailable
    /// native objects, a driver panic or a loop stopped before its result.
    pub fn run<T: 'static>(drive: impl FnMut() -> Poll<T> + 'static) -> io::Result<T> {
        objc2::rc::autoreleasepool(|_| Self::run_owned(drive))
    }
    fn run_owned<T: 'static>(drive: impl FnMut() -> Poll<T> + 'static) -> io::Result<T> {
        let _identity = Self::identity()?;
        let application = sdk::Application::new()?;
        let state = Rc::new(Driver {
            drive: RefCell::new(Some(drive)),
            result: RefCell::new(None),
            polling: Cell::new(false),
        });
        let callback_state = Rc::clone(&state);
        let stop = application.stopper()?;
        let failed_state = Rc::clone(&state);
        let failed_stop = stop.clone();
        let launch = sdk::Launch::new(
            &application,
            move || {
                if callback_state.polling.replace(true) {
                    return;
                }
                let _polling = Polling(&callback_state.polling);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if callback_state.result.borrow().is_some() {
                        return Poll::Pending;
                    }
                    let mut drive = callback_state.drive.borrow_mut();
                    match drive.as_mut() {
                        Some(drive) => drive(),
                        None => Poll::Pending,
                    }
                }));
                let completed = match result {
                    Ok(Poll::Pending) => None,
                    Ok(Poll::Ready(value)) => Some(Ok(value)),
                    Err(payload) => {
                        super::completion::dispose_panic(payload);
                        Some(Err(io::Error::other("application operation panicked")))
                    }
                };
                if let Some(completed) = completed {
                    *callback_state.result.borrow_mut() = Some(completed);
                    stop.stop();
                }
            },
            move |error| {
                *failed_state.result.borrow_mut() = Some(Err(error));
                failed_stop.stop();
            },
        )?;
        application.run();
        // Invalidate on the installing thread before releasing the driver.
        // NSTimer may retain an invalidated block briefly; clearing its driver
        // prevents that loan from retaining an original operation indefinitely.
        drop(launch);
        let drive = state.drive.borrow_mut().take();
        drop(drive);
        state.result.borrow_mut().take().unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "application stopped before its original operation completed",
            ))
        })
    }
}
struct Driver<F, T> {
    drive: RefCell<Option<F>>,
    result: RefCell<Option<io::Result<T>>>,
    polling: Cell<bool>,
}
struct Polling<'driver>(&'driver Cell<bool>);
impl Drop for Polling<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}
