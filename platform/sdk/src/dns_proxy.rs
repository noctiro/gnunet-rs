//! Application extension ABI for the shared Apple DNS service.
#![expect(
    unsafe_code,
    reason = "Borrowed native objects and callback blocks cross the C ABI"
)]

use crate::{GnBytes, INVALID, OK, SETUP_ERROR, config};
use block2::RcBlock;
use gnunet_native::dns_proxy::provider::{
    AppExtensionCallbacks, Controller, ProviderLimits, ShutdownHandle,
};
use std::{
    ffi::c_void,
    io::Write,
    path::PathBuf,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

#[repr(C)]
struct GnDnsProxyPaths {
    configuration: GnBytes,
    resources: GnBytes,
    binaries: GnBytes,
}

struct Paths {
    configuration: PathBuf,
    resources: PathBuf,
    binaries: PathBuf,
}

impl Paths {
    /// The caller keeps all three ranges readable during conversion.
    unsafe fn read(raw: &GnDnsProxyPaths) -> Option<Self> {
        // SAFETY: the caller lends the stated byte ranges for this call.
        unsafe {
            Some(Self {
                configuration: config::path(raw.configuration.text(config::MAX_PATH)?)?,
                resources: config::path(raw.resources.text(config::MAX_PATH)?)?,
                binaries: config::path(raw.binaries.text(config::MAX_PATH)?)?,
            })
        }
    }
}

struct GnDnsProxy {
    callbacks: AppExtensionCallbacks,
    shutdown: ShutdownHandle,
    worker: thread::JoinHandle<()>,
    stopped: Arc<AtomicBool>,
}

/// Starts one provider session and transfers one thread owner on success.
///
/// # Safety
/// Lend the original NEDNSProxyProvider and its start block, readable paths,
/// and a separate writable output. On error the block remains with the caller.
#[unsafe(no_mangle)]
unsafe extern "C" fn gnunet_dns_proxy_start(
    paths: *const GnDnsProxyPaths,
    provider: *mut c_void,
    completion: *mut c_void,
    out: *mut *mut GnDnsProxy,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    // SAFETY: the output is writable and distinct from borrowed input.
    unsafe { out.write(ptr::null_mut()) };
    if provider.is_null() || completion.is_null() {
        return INVALID;
    }
    // SAFETY: the caller keeps paths and their ranges readable for the call.
    let Some(paths) = (unsafe { paths.as_ref().and_then(|paths| Paths::read(paths)) }) else {
        return INVALID;
    };
    let Paths {
        configuration,
        resources,
        binaries,
    } = paths;
    let Ok((controller, callbacks)) = Controller::for_app_extension(ProviderLimits::default())
    else {
        return SETUP_ERROR;
    };
    let shutdown = controller.shutdown_handle();
    let Ok(worker) = thread::Builder::new()
        .name("gnunet-dns-provider".to_owned())
        .spawn(move || {
            if let Err(error) =
                gnunet_service_dns::run_app_extension(controller, &resources, &binaries)
            {
                let _written = writeln!(std::io::stderr().lock(), "gnunet-dns-proxy: {error}");
            }
        })
    else {
        return SETUP_ERROR;
    };
    // SAFETY: the original provider and native NSError completion block are
    // live through submission. Successful submission retains their owners.
    if unsafe { callbacks.start(provider, configuration, completion) }.is_err() {
        shutdown.request_shutdown();
        let _joined = worker.join();
        return SETUP_ERROR;
    }
    let owner = Box::new(GnDnsProxy {
        callbacks,
        shutdown,
        worker,
        stopped: Arc::new(AtomicBool::new(false)),
    });
    // SAFETY: the caller receives the one owning pointer in the original slot.
    unsafe { out.write(Box::into_raw(owner)) };
    OK
}

/// Admits a flow only during the original live session.
///
/// # Safety
/// The handle remains live and the provider and flow come from the same
/// NetworkExtension admission callback.
#[unsafe(no_mangle)]
unsafe extern "C" fn gnunet_dns_proxy_accept(
    proxy: *const GnDnsProxy,
    provider: *mut c_void,
    flow: *mut c_void,
) -> i32 {
    // SAFETY: the caller excludes destruction during this borrow.
    let Some(proxy) = (unsafe { proxy.as_ref() }) else {
        return 0;
    };
    if provider.is_null() || flow.is_null() {
        return 0;
    }
    // SAFETY: the original SDK objects are live during the callback.
    i32::from(unsafe { proxy.callbacks.accept(provider, flow) })
}

/// Submits the original stop and records exact native retirement.
///
/// # Safety
/// Lend the live host and the provider from its original stop callback.
#[unsafe(no_mangle)]
unsafe extern "C" fn gnunet_dns_proxy_stop(
    proxy: *const GnDnsProxy,
    provider: *mut c_void,
    reason: isize,
) -> i32 {
    // SAFETY: the caller excludes destruction during this borrow.
    let Some(proxy) = (unsafe { proxy.as_ref() }) else {
        return INVALID;
    };
    if provider.is_null() {
        return INVALID;
    }
    let stopped = Arc::clone(&proxy.stopped);
    let completion = RcBlock::new(move || stopped.store(true, Ordering::Release));
    // SAFETY: object and block use the original NetworkExtension stop ABI.
    if unsafe {
        proxy
            .callbacks
            .stop(provider, reason, RcBlock::as_ptr(&completion).cast())
    }
    .is_ok()
    {
        OK
    } else {
        proxy.shutdown.request_shutdown();
        SETUP_ERROR
    }
}

/// Consumes the host after failed startup or stop, and joins its original worker.
/// Success requires the native stop receipt and termination of the worker.
///
/// # Safety
/// Transfer one live owning pointer. Run off the worker and its callbacks.
#[unsafe(no_mangle)]
unsafe extern "C" fn gnunet_dns_proxy_join(proxy: *mut GnDnsProxy) -> i32 {
    if proxy.is_null() {
        return INVALID;
    }
    // SAFETY: the caller transfers its unique owner and excludes new use.
    let proxy = unsafe { Box::from_raw(proxy) };
    if proxy.worker.join().is_ok() && proxy.stopped.load(Ordering::Acquire) {
        OK
    } else {
        SETUP_ERROR
    }
}
