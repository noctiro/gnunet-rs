//! Complete dump fixtures and real read-only kernel queries; no TUN is created.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert dump evidence and original native errors"
)]
use super::*;
#[cfg(target_os = "freebsd")]
use crate::RouteQueryEvidence;
use crate::routes::netlink::wire::DIRECT_SCOPE;
use crate::{Epoch, Info};
#[cfg(target_os = "freebsd")]
use std::os::fd::AsRawFd;
use std::time::Duration;
use std::{cell::Cell, rc::Rc};
use tokio::time::Instant;

fn target() -> RouteQueryTarget {
    let table = if cfg!(target_os = "freebsd") { 0 } else { 254 };
    RouteQueryTarget {
        epoch: Epoch(Rc::new(crate::Stamp {
            alive: Cell::new(true),
            route_table: Some(table),
        })),
        table: Some(table),
        interface: Info {
            name: "query-vector".into(),
            index: 7,
            #[cfg(target_os = "linux")]
            mode: crate::Mode::RawIp,
            #[cfg(target_os = "freebsd")]
            mode: crate::Mode::FreeBsd,
        },
        destination: IpAddr::from([192, 0, 2, 0]),
        prefix: 24,
        gateway: None,
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
fn record_frame(index: u32, table: u32) -> Vec<u8> {
    let mut b = vec![0; 28];
    put16(&mut b, 4, 24);
    put16(&mut b, 6, 2);
    put32(&mut b, 8, 19);
    b[16] = libc::AF_INET as u8;
    b[17] = 24;
    b[20] = u8::try_from(table).unwrap_or(0);
    b[21] = 4;
    b[22] = DIRECT_SCOPE;
    b[23] = 1;
    attribute(&mut b, 15, &table.to_ne_bytes());
    attribute(&mut b, 1, &[192, 0, 2, 0]);
    attribute(&mut b, 4, &index.to_ne_bytes());
    #[cfg(target_os = "freebsd")]
    {
        attribute(&mut b, 10, &23u32.to_ne_bytes());
        attribute(&mut b, 14, &(libc::RTF_STATIC as u32).to_ne_bytes());
    }
    let n = b.len() as u32;
    put32(&mut b, 0, n);
    b
}
fn done() -> Vec<u8> {
    let mut b = vec![0; 20];
    put32(&mut b, 0, 20);
    put16(&mut b, 4, 3);
    // FreeBSD sends DONE with flags=0; MULTI on every route is still required.
    put32(&mut b, 8, 19);
    b
}
#[test]
fn only_complete_uninterrupted_exact_table_inventory_settles() -> io::Result<()> {
    let target = target();
    let table = target.table.ok_or_else(invalid)?;
    let frame = record_frame(7, table);
    let mut scan = Scan::default();
    assert!(reply(&frame, &target, 19, 41, &mut scan, &[])?.is_none());
    let finished = reply(&done(), &target, 19, 41, &mut scan, &[])?.ok_or_else(invalid)?;
    let RouteQueryOutcome::Exact(record) = finished.outcome else {
        return Err(io::Error::other("exact direct route was not recognized"));
    };
    assert_eq!(record.interface(), 7);
    assert_eq!(record.table(), Some(table));
    assert!(record.direct());
    assert_eq!(finished.evidence, DUMP_EVIDENCE);

    let mut other = record_frame(7, table + 1);
    other.extend(done());
    let finished =
        reply(&other, &target, 19, 41, &mut Scan::default(), &[])?.ok_or_else(invalid)?;
    assert!(matches!(finished.outcome, RouteQueryOutcome::Absent));
    let mut wrong_oif = record_frame(8, table);
    wrong_oif.extend(done());
    let finished =
        reply(&wrong_oif, &target, 19, 41, &mut Scan::default(), &[])?.ok_or_else(invalid)?;
    assert!(matches!(finished.outcome, RouteQueryOutcome::Different(_)));
    let mut duplicate = frame.clone();
    duplicate.extend(&frame);
    duplicate.extend(done());
    let finished =
        reply(&duplicate, &target, 19, 41, &mut Scan::default(), &[])?.ok_or_else(invalid)?;
    assert!(matches!(
        finished.outcome,
        RouteQueryOutcome::Unknown(RouteQueryProblem::Ambiguous { records: 2 })
    ));
    let mut rejected = done();
    let code = if cfg!(target_os = "freebsd") {
        libc::EINVAL
    } else {
        -libc::EINVAL
    };
    rejected[16..20].copy_from_slice(&code.to_ne_bytes());
    assert_eq!(
        reply(&rejected, &target, 19, 41, &mut Scan::default(), &[])
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(libc::EINVAL)
    );
    let mut interrupted = done();
    put16(&mut interrupted, 6, 0x10);
    assert!(reply(&interrupted, &target, 19, 41, &mut Scan::default(), &[]).is_err());
    let mut malformed = frame;
    put16(&mut malformed, 28, 3);
    assert!(reply(&malformed, &target, 19, 41, &mut Scan::default(), &[]).is_err());
    Ok(())
}

#[cfg(target_os = "freebsd")]
#[test]
fn native_path_flags_are_required_and_blackhole_is_not_exact() -> io::Result<()> {
    let target = target();
    let mut frame = record_frame(7, 0);
    // Last attribute is native RTA_RTFLAGS, not rtmsg.rtm_flags.
    let value = frame.len() - 4;
    put32(&mut frame, value, libc::RTF_BLACKHOLE as u32);
    frame.extend(done());
    let finished =
        reply(&frame, &target, 19, 41, &mut Scan::default(), &[])?.ok_or_else(invalid)?;
    assert!(matches!(finished.outcome, RouteQueryOutcome::Different(_)));
    frame.truncate(value - 4); // remove native path flags
    let n = frame.len() as u32;
    put32(&mut frame, 0, n);
    frame.extend(done());
    let finished =
        reply(&frame, &target, 19, 41, &mut Scan::default(), &[])?.ok_or_else(invalid)?;
    assert!(
        matches!(finished.outcome, RouteQueryOutcome::Different(record) if record.unsupported())
    );
    Ok(())
}

#[cfg(target_os = "freebsd")]
#[test]
fn native_loopback_inventory_round_trip_is_read_only() -> io::Result<()> {
    let mut target = target();
    target.interface.name = "lo0".into();
    target.interface.index = crate::platform::index("lo0")?;
    let fib = crate::platform::interface_fib(&target.interface)?;
    target.table = Some(fib);
    for destination in [
        IpAddr::from([127, 0, 0, 1]),
        IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
    ] {
        target.destination = destination;
        target.prefix = if destination.is_ipv4() { 32 } else { 128 };
        let session = prepare(&target, 19)?;
        assert_eq!(session.frame.len(), 36);
        assert_eq!(word(&session.frame, 32)?, fib); // Explicit even for FIB 0.
        assert_eq!(
            nix::unistd::write(&session.fd, &session.frame)?,
            session.frame.len()
        );
        let mut scan = Scan::default();
        let mut bytes = [0u8; 32768];
        let mut complete = false;
        let until = std::time::Instant::now() + Duration::from_secs(2);
        for _ in 0..128 {
            let mut poll = libc::pollfd {
                fd: session.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            #[expect(
                unsafe_code,
                reason = "poll borrows one initialized live pollfd for a finite read-only kernel wait"
            )]
            // SAFETY: this one-element array remains exclusive/live for the call.
            let ready = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    until
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis()
                        .min(2000) as i32,
                )
            };
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            if ready == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let n = super::super::super::receive(&session.fd, &mut bytes)?;
            if let Some(result) = reply(
                &bytes[..n],
                &target,
                19,
                session.pid,
                &mut scan,
                &session.frame,
            )? {
                assert!(matches!(result.outcome, RouteQueryOutcome::Exact(_)));
                assert_eq!(result.evidence, RouteQueryEvidence::FreeBsdDump);
                complete = true;
                break;
            }
        }
        assert!(complete, "bounded kernel route dump did not finish");
        nix::unistd::close(session.fd)?;
    }
    Ok(())
}
