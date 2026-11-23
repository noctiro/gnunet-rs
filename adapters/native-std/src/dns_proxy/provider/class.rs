//! The macOS system extension's original Objective-C principal class.
use super::{
    PROVIDER_CLASS_NAME, bridge,
    native::{
        NativeIncoming, NativeProvider, StartCompletion, StopCompletion, boundary, fail_start,
    },
};
use block2::Block;
use objc2::{
    ClassType, define_class, extern_class,
    runtime::{AnyClass, AnyObject, NSObject},
};
use objc2_foundation::{NSDictionary, NSError, NSString, NSUTF8StringEncoding, ns_string};
use std::{io, path::PathBuf};

extern_class!(
    #[unsafe(super(NSObject))]
    struct NEProvider;
);
extern_class!(
    #[unsafe(super(NEProvider, NSObject))]
    struct NEDNSProxyProvider;
);

// SAFETY: This direct subclass has no Rust instance variables. Every native
// callback uses the bounded synchronized controller, and the exact inherited
// lifecycle signatures are those of NEDNSProxyProvider.h.
define_class!(
    #[unsafe(super(NEDNSProxyProvider, NEProvider, NSObject))]
    #[name = "GNUnetDNSProxyProvider"]
    struct GNUnetDNSProxyProvider;

    impl GNUnetDNSProxyProvider {
        #[unsafe(method(startProxyWithOptions:completionHandler:))]
        fn start_proxy(&self, options: Option<&NSDictionary<NSString, AnyObject>>, completion: &Block<dyn Fn(*mut NSError)>) {
            boundary(|| fail_start(completion), || {
                let callback = match StartCompletion::copy(completion) { Ok(callback) => callback, Err(_) => { fail_start(completion); return; } };
                let result = configuration(options).and_then(|configuration| {
                    let provider = self.provider()?;
                    let bridge = bridge::registered().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "DNS provider has no controller"))?;
                    bridge.start(provider, configuration, callback);
                    Ok(())
                });
                if let Err(error) = result && let Some(bridge) = bridge::registered() { bridge.failed_start(error); }
            });
        }
        #[unsafe(method(stopProxyWithReason:completionHandler:))]
        fn stop_proxy(&self, reason: isize, completion: &Block<dyn Fn()>) {
            boundary(|| self.cancel(), || {
                let provider = match self.provider() { Ok(provider) => provider, Err(_) => return, };
                let callback = match StopCompletion::copy(completion) { Ok(callback) => callback, Err(_) => { provider.cancel(); return; } };
                match bridge::registered() {
                    Some(bridge) => {
                        if let Err(provider) = bridge.stop(provider, reason, callback) {
                            provider.cancel();
                        }
                    }
                    None => provider.cancel(),
                }
            });
        }
        #[unsafe(method(handleNewFlow:))]
        fn handle_flow(&self, flow: &AnyObject) -> bool {
            boundary(|| false, || self.accept(flow))
        }
        #[unsafe(method(handleNewUDPFlow:initialRemoteFlowEndpoint:))]
        fn handle_udp(&self, flow: &AnyObject, _endpoint: &AnyObject) -> bool {
            boundary(|| false, || self.accept(flow))
        }
    }
);
impl GNUnetDNSProxyProvider {
    fn provider(&self) -> io::Result<NativeProvider> {
        // SAFETY: Every instance of this defined class has the NSObject prefix;
        // it is retained only during its original native callback invocation.
        let object = unsafe { &*(self as *const Self).cast::<AnyObject>() };
        NativeProvider::retain(object)
    }
    fn cancel(&self) {
        if let Ok(provider) = self.provider() {
            provider.cancel();
        }
    }
    fn accept(&self, flow: &AnyObject) -> bool {
        let Some(bridge) = bridge::registered() else {
            return false;
        };
        let Ok(provider) = self.provider() else {
            return false;
        };
        let Some((native, udp)) = NativeIncoming::retain(flow) else {
            return false;
        };
        bridge.accept(&provider, native, udp)
    }
}

pub(super) fn register() -> io::Result<()> {
    super::availability::check()?;
    if AnyClass::get(c"NEDNSProxyProvider").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native DNS proxy provider class unavailable",
        ));
    }
    let class = GNUnetDNSProxyProvider::class();
    if class.name().to_bytes() != PROVIDER_CLASS_NAME.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS provider class name mismatch",
        ));
    }
    Ok(())
}

fn configuration(options: Option<&NSDictionary<NSString, AnyObject>>) -> io::Result<PathBuf> {
    let value = options
        .and_then(|options| options.objectForKey(ns_string!("GNUNET_CONFIG")))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS provider requires GNUNET_CONFIG",
            )
        })?;
    let value = value.downcast::<NSString>().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "GNUNET_CONFIG is not a string")
    })?;
    if value.length() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GNUNET_CONFIG exceeds its bound",
        ));
    }
    let length = value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
    let bytes = value.UTF8String();
    if length == 0 || length > 4096 || bytes.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GNUNET_CONFIG is not bounded UTF-8",
        ));
    }
    // SAFETY: NSString owns this UTF-8 representation for the live local borrow;
    // its exact encoding length was checked before any Rust allocation.
    let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), length) };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid UTF-8 GNUNET_CONFIG"))?;
    let path = PathBuf::from(text);
    super::native::configuration_path(&path)?;
    Ok(path)
}
