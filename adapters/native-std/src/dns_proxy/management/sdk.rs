//! Exact NetworkExtension preference selectors and retained native objects.
use super::{Configuration, Mode, Operation, Snapshot, configuration};
use block2::Block;
use objc2::{
    extern_class, msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, NSObject},
};
use objc2_foundation::{NSDictionary, NSError, NSString, NSUTF8StringEncoding, ns_string};
use std::{io, path::PathBuf};

extern_class!(
    #[unsafe(super(NSObject))]
    struct NEDNSProxyManager;
);
extern_class!(
    #[unsafe(super(NSObject))]
    struct NEVPNProtocol;
);
extern_class!(
    #[unsafe(super(NEVPNProtocol, NSObject))]
    struct NEDNSProxyProviderProtocol;
);

#[derive(Clone)]
pub(super) struct NativeManager(Retained<NEDNSProxyManager>);
// SAFETY: NEDNSProxyManager.h explicitly documents instances as thread safe.
// The public owner serializes all operations; native callbacks only read after
// their original successful load, before its completion becomes observable.
unsafe impl Send for NativeManager {}
// SAFETY: The SDK thread-safety contract covers this retained singleton; no
// unsynchronized Rust data is stored in the Objective-C object.
unsafe impl Sync for NativeManager {}
impl NativeManager {
    pub(super) fn shared() -> io::Result<Self> {
        let class = AnyClass::get(c"NEDNSProxyManager").ok_or_else(unavailable)?;
        // SAFETY: Exact documented singleton selector returns a live +0 object;
        // msg_send's Retained result acquires the independent strong reference.
        let value: Option<Retained<NEDNSProxyManager>> = unsafe { msg_send![class, sharedManager] };
        value
            .map(Self)
            .ok_or_else(|| io::Error::other("DNS proxy manager returned null"))
    }
    pub(super) fn begin(&self, operation: Operation, callback: &Block<dyn Fn(*mut NSError)>) {
        // SAFETY: All three methods copy the exact escaping NSError completion.
        // Its Rust state and original native manager are independently retained
        // until the copied block's final disposal, including after owner Drop.
        unsafe {
            let _: () = match operation {
                Operation::Load => {
                    msg_send![&*self.0, loadFromPreferencesWithCompletionHandler: callback]
                }
                Operation::Apply | Operation::Disable => {
                    msg_send![&*self.0, saveToPreferencesWithCompletionHandler: callback]
                }
                Operation::Remove => {
                    msg_send![&*self.0, removeFromPreferencesWithCompletionHandler: callback]
                }
            };
        }
    }
    pub(super) fn apply(&self, prepared: &Prepared, mode: Mode) {
        // SAFETY: These exact properties retain/copy their fully prepared SDK
        // values. No callback is active and the original ownership was checked.
        unsafe {
            let _: () = msg_send![&*self.0, setProviderProtocol: &*prepared.0];
            let _: () =
                msg_send![&*self.0, setLocalizedDescription: ns_string!("GNUnet DNS Proxy")];
            let _: () = msg_send![&*self.0, setEnabled: mode == Mode::Enabled];
        }
    }
    pub(super) fn disable(&self) {
        // SAFETY: Exact BOOL setter on the original owned manager; preserves its
        // original protocol and every provider-specific field.
        let _: () = unsafe { msg_send![&*self.0, setEnabled: false] };
    }
    pub(super) fn snapshot(&self) -> io::Result<Snapshot> {
        // SAFETY: Exact nullable strong providerProtocol and BOOL getters on the
        // original thread-safe singleton; result references are retained.
        let (protocol, enabled): (Option<Retained<NEDNSProxyProviderProtocol>>, bool) = unsafe {
            (
                msg_send![&*self.0, providerProtocol],
                msg_send![&*self.0, isEnabled],
            )
        };
        let mut snapshot = Snapshot {
            present: protocol.is_some(),
            enabled,
            identifier: None,
            file: None,
            file_error: None,
        };
        let Some(protocol) = protocol else {
            return Ok(snapshot);
        };
        // SAFETY: Exact nullable copied NSString property of the original
        // retained provider protocol.
        let identifier: Option<Retained<NSString>> =
            unsafe { msg_send![&*protocol, providerBundleIdentifier] };
        // SAFETY: Exact nullable copied dictionary property of the same original
        // retained protocol; the returned object acquires an independent retain.
        let values: Option<Retained<NSDictionary<NSString, AnyObject>>> =
            unsafe { msg_send![&*protocol, providerConfiguration] };
        snapshot.identifier = identifier
            .as_ref()
            .map(|value| text(value, 255))
            .transpose()?;
        if let Some(value) =
            values.and_then(|values| values.objectForKey(ns_string!("GNUNET_CONFIG")))
        {
            let decoded = (|| {
                let value = value.downcast::<NSString>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "loaded GNUNET_CONFIG is not a string",
                    )
                })?;
                let file = PathBuf::from(text(&value, 4096)?);
                configuration::path(&file)?;
                Ok::<_, io::Error>(file)
            })();
            match decoded {
                Ok(file) => snapshot.file = Some(file),
                // Keep ownership independent of malformed vendor settings so
                // an explicitly owned configuration can be repaired or retired.
                Err(error) => snapshot.file_error = Some(error.to_string()),
            }
        }
        Ok(snapshot)
    }
}

pub(super) struct Prepared(Retained<NEDNSProxyProviderProtocol>);
impl Prepared {
    pub(super) fn new(configuration: &Configuration) -> io::Result<Self> {
        let class = AnyClass::get(c"NEDNSProxyProviderProtocol").ok_or_else(unavailable)?;
        let identifier = NSString::from_str(&configuration.identifier);
        let file = NSString::from_str(configuration::path(&configuration.file)?);
        let values = NSDictionary::from_slices(&[ns_string!("GNUNET_CONFIG")], &[&*file]);
        // SAFETY: Exact inherited NSObject initializer yields an independently
        // owned protocol. Its properties copy the validated immutable values.
        let value: Option<Retained<NEDNSProxyProviderProtocol>> = unsafe { msg_send![class, new] };
        let value =
            value.ok_or_else(|| io::Error::other("DNS proxy provider protocol returned null"))?;
        // SAFETY: Exact copied NSString/dictionary properties; both inputs remain
        // live throughout the setters and contain only property-list strings.
        unsafe {
            let _: () = msg_send![&*value, setProviderBundleIdentifier: &*identifier];
            let _: () = msg_send![&*value, setProviderConfiguration: &*values];
        }
        Ok(Self(value))
    }
}
pub(super) fn result(error: *mut NSError) -> io::Result<()> {
    super::super::sdk::error_result(error)
}
fn text(value: &NSString, bound: usize) -> io::Result<String> {
    if value.length() > bound {
        return Err(invalid_string());
    }
    let length = value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
    let pointer = value.UTF8String();
    if length > bound || pointer.is_null() {
        return Err(invalid_string());
    }
    // SAFETY: NSString owns this exact UTF-8 encoding for the live local borrow.
    // Both UTF-16 and byte lengths were bounded before allocation or reading.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_string())?;
    if text.contains('\0') {
        return Err(invalid_string());
    }
    Ok(text.to_owned())
}
fn invalid_string() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "DNS proxy preference string is not bounded UTF-8",
    )
}
fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native DNS proxy preference API is unavailable",
    )
}
