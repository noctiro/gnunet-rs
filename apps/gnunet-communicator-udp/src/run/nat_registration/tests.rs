//! Real private Unix registration streams and loopback UDP. Notifications are
//! component fixtures, not evidence of a NAT mapping or official C service.
use super::*;
use crate::addresses::{Failure as AddressFailure, NatRefusal};
use gnunet_service_runtime::{clock::SystemClock, connection::Connection, local::Listener};
use gnunet_types::Error as Fault;
use std::{net::SocketAddr, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
fn check(value: bool) -> Result<(), Cause> {
    if value {
        Ok(())
    } else {
        Err("NAT registration recovery regression".into())
    }
}
async fn frame(stream: &mut Connection) -> Result<Vec<u8>, Cause> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    check(size >= 4)?;
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn registered<'instance>(
    observer: &mut Observer<'instance>,
    listener: &Listener,
) -> Result<(nat::Session<'instance>, Connection), Cause> {
    let receive = async {
        let (stream, _) = listener.accept().await?;
        let mut stream = Connection::from_unix(stream);
        let request = frame(&mut stream).await?;
        check(matches!(
            nat::ipc::Request::decode(&request, nat::native_profile()?)?,
            nat::ipc::Request::Register { protocol: 17, .. }
        ))?;
        Ok::<_, Cause>(stream)
    };
    let send = async {
        loop {
            if let nat::Progress::Written(session, _, _, nat::Command::Register, _) =
                poll_fn(|cx| observer.poll(cx, None)).await?
            {
                return Ok::<_, Cause>(session);
            }
        }
    };
    let (session, stream) = tokio::join!(send, receive);
    Ok((session?, stream?))
}
async fn notification<'instance>(
    observer: &mut Observer<'instance>,
    stream: &mut Connection,
    address: SocketAddr,
    add_remove: i32,
) -> Result<nat::Progress<'instance>, Cause> {
    let profile = nat::native_profile()?;
    let SocketAddr::V4(address) = address else {
        return Err("IPv4 fixture required".into());
    };
    let mut raw = [0; 28];
    let size = nat::ipc::Address::V4 {
        ip: address.ip().octets(),
        port: address.port(),
    }
    .encode(profile, &mut raw)?;
    let response = nat::ipc::Response::AddressChange {
        add_remove,
        class: nat::ipc::AddressClass::GLOBAL,
        address: nat::ipc::RawAddress::decode(&raw[..size], profile)?,
    };
    let mut bytes = vec![0; response.encoded_len(profile)?];
    response.encode(profile, &mut bytes)?;
    stream.write_all(&bytes).await?;
    loop {
        let event = poll_fn(|cx| observer.poll(cx, None)).await?;
        if matches!(event, nat::Progress::Notification { .. }) {
            return Ok(event);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn absolute_clock_registration_recovers_source_and_rejects_only_the_full_claim()
-> Result<(), Cause> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut nonce = [0; 8]; getrandom::fill(&mut nonce)?;
        let scratch = Scratch(std::env::temp_dir().join(format!("udp-nat-{:016x}", u64::from_be_bytes(nonce))));
        gnunet_service_runtime::private_parents(&scratch.0.join(".owner"))?;
        let path = scratch.0.join("n");
        let listener = Listener::bind(&path)?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        check(clock.sample()?.now.as_micros() > 30_000_000)?;
        let source = EndpointSource::unix_with_clock(path, clock);
        let instance = nat::Instance::new();
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let bound = udp.local_addr()?;
        let mut observer = Observer::new(&instance, source, &[bound])?;
        check(observer.registration()?.registered_submission() == nat::Submission::Unsent)?;
        let mut addresses = Addresses::new(2, 1024, Duration::from_secs(30))?;
        addresses.replace_interfaces(&[bound], &mut |_| Ok(1))?;
        let (first, mut stream) = registered(&mut observer, &listener).await?;
        let public = "192.0.2.1:2086".parse()?;
        let other = "192.0.2.2:2086".parse()?;
        let event = notification(&mut observer, &mut stream, public, 1).await?;
        check(matches!(addresses.observe_nat(observer.registration()?, &event, &mut |_| Ok(3))?, NatObservation::Accepted))?;
        observer.registration_mut()?.release_notification()?;
        check(addresses.report().claims == 2)?;
        let event = notification(&mut observer, &mut stream, other, 1).await?;
        check(matches!(addresses.observe_nat(observer.registration()?, &event, &mut |_| Ok(3))?, NatObservation::Rejected { address, reason: NatRefusal::Capacity } if address == other))?;
        observer.registration_mut()?.release_notification()?;
        // The next deletion is not pinned behind an unadmittable ADD.
        let event = notification(&mut observer, &mut stream, public, 0).await?;
        check(matches!(addresses.observe_nat(observer.registration()?, &event, &mut |_| Ok(3))?, NatObservation::Accepted))?;
        observer.registration_mut()?.release_notification()?;
        check(addresses.report().claims == 1)?;
        let event = notification(&mut observer, &mut stream, public, 1).await?;
        check(matches!(addresses.observe_nat(observer.registration()?, &event, &mut |_| Ok(3))?, NatObservation::Accepted))?;
        observer.registration_mut()?.release_notification()?;
        drop(stream);
        let ended = loop {
            let event = poll_fn(|cx| observer.poll(cx, None)).await?;
            if matches!(event, nat::Progress::Ended(_)) { break event; }
        };
        check(matches!(addresses.observe_nat(observer.registration()?, &ended, &mut |_| Ok(3))?, NatObservation::Retired))?;
        let nat::Progress::Ended(ref end) = ended else { return Err("expected original End".into()); };
        check(matches!(end.source.cause, nat::Cause::Eof) && matches!(end.source.initial, nat::Submission::Written { .. }))?;
        check(matches!(observer.retired(end)?, Retirement::Recovering) && addresses.report().claims == 1)?;
        // Independent UDP traffic continues on the exact original loopback owner
        // while the NAT observer is waiting; this is not encrypted peer coverage.
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        sender.send_to(b"original", bound).await?;
        let mut bytes = [0; 8];
        check(udp.recv(&mut bytes).await? == 8 && &bytes == b"original")?;
        let (second, mut stream) = registered(&mut observer, &listener).await?;
        check(first != second && udp.local_addr()? == bound)?;
        let event = notification(&mut observer, &mut stream, public, 1).await?;
        check(matches!(addresses.observe_nat(observer.registration()?, &event, &mut |_| Ok(3))?, NatObservation::Accepted))?;
        observer.registration_mut()?.release_notification()?;
        check(matches!(addresses.observe_nat(observer.registration()?, &ended, &mut |_| Ok(3)), Err(AddressFailure::Core(Fault::StaleGeneration)))
            && addresses.report().claims == 2)?;
        check(observer.close().is_some())?;
        Ok(())
    }).await?
}

#[test]
fn recovery_keeps_clock_ownership_and_resource_invariants_terminal() -> Result<(), Cause> {
    check(
        recoverable(&nat::Cause::Eof)
            && recoverable(&nat::Cause::InputDeadline)
            && recoverable(&nat::Cause::Error(nat::Error::Protocol(Fault::Capacity)))
            && !recoverable(&nat::Cause::Clock(Fault::TimeUncertain))
            && !recoverable(&nat::Cause::Protocol(Fault::StaleGeneration))
            && !recoverable(&nat::Cause::Io(io::Error::from(io::ErrorKind::OutOfMemory)))
            && !recoverable(&nat::Cause::Cancelled),
    )
}
