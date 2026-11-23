//! Check the actual runtime classes before accepting a provider session.
use objc2::{runtime::AnyClass, sel};
use std::io;

pub(super) fn check() -> io::Result<()> {
    let udp = AnyClass::get(c"NEAppProxyUDPFlow").ok_or_else(unavailable)?;
    for selector in [
        sel!(localFlowEndpoint),
        sel!(openWithLocalFlowEndpoint:completionHandler:),
        sel!(readDatagramsAndFlowEndpointsWithCompletionHandler:),
        sel!(writeDatagrams:sentByFlowEndpoints:completionHandler:),
    ] {
        if udp.instance_method(selector).is_none() {
            return Err(unavailable());
        }
    }
    let tcp = AnyClass::get(c"NEAppProxyTCPFlow").ok_or_else(unavailable)?;
    for selector in [
        sel!(remoteFlowEndpoint),
        sel!(openWithLocalFlowEndpoint:completionHandler:),
        sel!(readDataWithCompletionHandler:),
        sel!(writeData:withCompletionHandler:),
    ] {
        if tcp.instance_method(selector).is_none() {
            return Err(unavailable());
        }
    }
    Ok(())
}
fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native DNS flow selectors require macOS 15 or iOS 18",
    )
}
