//! Real local socket-pair reactor tests, no public network or descriptor stealing.
#![cfg(unix)]
#![expect(
    clippy::expect_used,
    reason = "Finite owned-resource tests fail immediately on unexpected OS/reactor results"
)]
use gnunet_service_runtime::readiness::RegisteredReadiness;
use std::{
    future::poll_fn,
    io::{Read, Write},
    os::fd::OwnedFd,
    os::unix::net::UnixStream,
    time::Duration,
};
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("local reactor")
}
#[test]
fn readiness_never_consumes_bytes_and_cached_hints_are_rechecked() {
    runtime().block_on(async {
        let (a, mut b) = UnixStream::pair().expect("own pair");
        a.set_nonblocking(true).expect("nonblocking");
        let port = RegisteredReadiness::new(OwnedFd::from(a)).expect("stable registration");
        b.write_all(b"first").expect("own data");
        let ready = poll_fn(|cx| port.poll_ready(cx))
            .await
            .expect("actual readiness");
        assert!(ready.readable);
        let mut bytes = [0; 5];
        assert_eq!(
            nix::unistd::read(port.as_fd(), &mut bytes).expect("actual consumer"),
            5
        );
        assert_eq!(&bytes, b"first");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), poll_fn(|cx| port.poll_ready(cx)))
                .await
                .is_err(),
            "cached hint is not fresh level readiness"
        );
        b.write_all(b"next").expect("new data");
        assert!(
            poll_fn(|cx| port.poll_ready(cx))
                .await
                .expect("fresh level")
                .readable
        );
        let mut bytes = [0; 4];
        assert_eq!(
            nix::unistd::read(port.as_fd(), &mut bytes).expect("actual read"),
            4
        );
        assert_eq!(&bytes, b"next");
    });
}
#[test]
fn dropping_pending_wait_retains_the_original_owned_resource() {
    runtime().block_on(async {
        let (a, mut b) = UnixStream::pair().expect("own pair");
        a.set_nonblocking(true).expect("nonblocking");
        let port = RegisteredReadiness::new(OwnedFd::from(a)).expect("stable registration");
        assert!(
            tokio::time::timeout(Duration::from_millis(5), poll_fn(|cx| port.poll_ready(cx)))
                .await
                .is_err()
        );
        b.write_all(b"x").expect("after canceled future");
        assert!(
            poll_fn(|cx| port.poll_ready(cx))
                .await
                .expect("still registered")
                .readable
        );
        let owned = port.into_owned();
        let mut socket = UnixStream::from(owned);
        socket.set_nonblocking(false).expect("new owner");
        let mut byte = [0];
        socket
            .read_exact(&mut byte)
            .expect("ownership survived deregistration");
        assert_eq!(byte, [b'x']);
    });
}
#[test]
fn real_hangup_is_classified_without_reading_or_claiming_payload() {
    runtime().block_on(async {
        let (a, b) = UnixStream::pair().expect("own pair");
        a.set_nonblocking(true).expect("nonblocking");
        let port = RegisteredReadiness::new(OwnedFd::from(a)).expect("stable registration");
        drop(b);
        let ready = poll_fn(|cx| port.poll_ready(cx))
            .await
            .expect("actual hangup");
        assert!(ready.hangup);
        assert!(!ready.error);
        let mut byte = [0];
        assert_eq!(
            nix::unistd::read(port.as_fd(), &mut byte).expect("actual EOF consumer"),
            0
        );
    });
}
