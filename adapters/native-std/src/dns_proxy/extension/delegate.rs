//! Original delegate dispositions with panic containment and deferred loan release.
use super::sdk::RequestDelegate;
use super::{
    Finished, ReplacementDecision, ReplacementPolicy, contain,
    registry::{self, Key, Release},
    sdk,
    state::Progress,
};
use crate::dns_proxy::completion::Publisher;
use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, rc::Retained};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString};
use std::{cell::RefCell, io, rc::Rc};

pub(super) struct Ivars {
    pub key: Key,
    pub identifier: Retained<NSString>,
    pub replacement: ReplacementPolicy,
    pub progress: Rc<Progress>,
    pub publish: RefCell<Option<Publisher<io::Result<Finished>>>>,
    pub release: RefCell<Option<Release>>,
}
// SAFETY: NSObject permits subclassing. All original callbacks are requested on
// the main dispatch queue; the defined object and its Rust ivars stay confined
// to that thread. Every required protocol signature matches SystemExtensions.h.
define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "GNUnetSystemExtensionRequestDelegate"]
    #[ivars = Ivars]
    pub(super) struct Delegate;
    unsafe impl NSObjectProtocol for Delegate {}
    unsafe impl RequestDelegate for Delegate {
        #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
        fn replacement(
            &self,
            request: &sdk::Request,
            existing: &sdk::Properties,
            proposed: &sdk::Properties,
        ) -> isize {
            contain(0, || self.decide(request, existing, proposed))
        }
        #[unsafe(method(requestNeedsUserApproval:))]
        fn approval(&self, request: &sdk::Request) {
            contain((), || {
                if registry::matches(self.ivars().key, request) {
                    self.ivars().progress.approval();
                }
            });
        }
        #[unsafe(method(request:didFinishWithResult:))]
        fn finished(&self, request: &sdk::Request, result: isize) {
            contain((), || {
                let result = match result {
                    0 => Ok(Finished::Completed),
                    1 => Ok(Finished::AfterReboot),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown system-extension completion disposition",
                    )),
                };
                self.complete(request, result);
            });
        }
        #[unsafe(method(request:didFailWithError:))]
        fn failed(&self, request: &sdk::Request, error: &NSError) {
            contain((), || {
                // SAFETY: The original delegate's NSError is live throughout
                // this callback; the shared boundary retains its domain/cause.
                let cause = super::super::sdk::error_result((error as *const NSError).cast_mut());
                let result = cause.and_then(|()| {
                    Err(io::Error::other(
                        "native extension failure supplied no NSError",
                    ))
                });
                self.complete(request, result);
            });
        }
    }
);
impl Delegate {
    pub(super) fn new(main: MainThreadMarker, ivars: Ivars) -> Retained<Self> {
        let allocated = Self::alloc(main).set_ivars(ivars);
        // SAFETY: Exact NSObject initializer on this fully initialized subclass.
        unsafe { msg_send![super(allocated), init] }
    }
    fn decide(
        &self,
        request: &sdk::Request,
        existing: &sdk::Properties,
        proposed: &sdk::Properties,
    ) -> isize {
        let ivars = self.ivars();
        if !registry::matches(ivars.key, request) {
            return 0;
        }
        // SystemExtensions.h restricts this callback to the same team and
        // bundle identifiers. Team ID is not exposed by the properties API;
        // retain that OS prerequisite and independently verify both bundle IDs.
        let same = sdk::same_identifier(existing, &ivars.identifier)
            && sdk::same_identifier(proposed, &ivars.identifier);
        let (old, old_short) = sdk::versions(existing);
        let (new, new_short) = sdk::versions(proposed);
        let versions = old
            .zip(old_short)
            .zip(new.zip(new_short))
            .map(|((a, b), (c, d))| [a, b, c, d]);
        let decision = ivars.replacement.decide(same, versions);
        ivars.progress.replacement(old, new, decision);
        isize::from(decision == ReplacementDecision::Upgrade)
    }
    fn complete(&self, request: &sdk::Request, result: io::Result<Finished>) {
        let ivars = self.ivars();
        let Some(loan) = registry::take(ivars.key, request) else {
            return;
        };
        let release = ivars.release.borrow_mut().take();
        ivars.progress.finish();
        let publish = ivars.publish.borrow_mut().take();
        if let Some(publish) = publish {
            publish.publish(result);
        }
        if let Some(release) = release {
            release.submit(loan);
        }
    }
}
