//! Native ACK vectors; these are protocol inputs, not successful route mutations.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Check correlated ACK/error vectors"
)]
use super::super::RouteOutcome;
use super::*;

#[test]
fn ack_retains_native_error_sign_and_original_request() -> io::Result<()> {
    let mut request = [0u8; 16];
    put32(&mut request, 0, 52);
    put16(&mut request, 4, 24);
    put16(&mut request, 6, 0x605);
    put32(&mut request, 8, 19);
    put32(&mut request, 12, 41);
    let mut reply = [0u8; 36];
    put32(&mut reply, 0, 36);
    put16(&mut reply, 4, 2);
    put32(&mut reply, 8, 19);
    reply[20..].copy_from_slice(&request);
    assert!(matches!(
        ack(&reply, 19, 24, 41, 7, &request)?,
        Some(Ok(()))
    ));
    let error = if cfg!(target_os = "freebsd") {
        libc::EEXIST
    } else {
        -libc::EEXIST
    };
    reply[16..20].copy_from_slice(&error.to_ne_bytes());
    let Some(Err(observed)) = ack(&reply, 19, 24, 41, 7, &request)? else {
        return Err(io::Error::other("native rejection was lost"));
    };
    assert_eq!(observed.raw_os_error(), Some(libc::EEXIST));
    reply[16..20].copy_from_slice(&(-error).to_ne_bytes());
    assert!(ack(&reply, 19, 24, 41, 7, &request).is_err());
    reply[16..20].fill(0);
    reply[32] ^= 1; // echoed original sender differs
    assert!(ack(&reply, 19, 24, 41, 7, &request).is_err());
    assert!(ack(&reply, 20, 24, 41, 7, &request)?.is_none());
    put32(&mut reply, 0, 35);
    assert!(ack(&reply, 19, 24, 41, 7, &request).is_err());
    assert!(kernel_error(i32::MIN).is_err());
    Ok(())
}

#[test]
fn missing_route_errno_is_rejection_not_unsent_or_uncertainty() {
    assert!(
        RouteOutcome::KernelAck(Err(io::Error::from_raw_os_error(libc::ESRCH)))
            .is_missing_route_rejection()
    );
    assert!(
        !RouteOutcome::Unsent(io::Error::from_raw_os_error(libc::ESRCH))
            .is_missing_route_rejection()
    );
    assert!(
        !RouteOutcome::Uncertain(io::Error::from_raw_os_error(libc::ESRCH))
            .is_missing_route_rejection()
    );
    assert!(!RouteOutcome::KernelAck(Ok(())).is_missing_route_rejection());
}
