//! Actual Unix FIFO witnesses for the production SDK owner; not a C daemon test.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real byte-stream assertions identify incorrect credit ownership"
)]
use gnunet_client::transport::{
    Event, Instance, PeerId, Request, Response, SendId, SendOutcome, Start, TransportClient,
};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PEER: PeerId = PeerId([17; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
fn frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h)?;
    let size = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if size < 4 {
        return Err("bad frame size".into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}
fn emit(stream: &mut UnixStream, response: Response<'_>) -> Result<usize> {
    let mut out = vec![0; 65535];
    let n = response.encode(&mut out)?;
    for part in out[..n].chunks(3) {
        stream.write_all(part)?;
    }
    Ok(n)
}
fn tracked(
    stream: &mut UnixStream,
    owner: &mut TransportClient<'_, 2, 4, 8>,
    send: SendId<'_>,
    bytes: &[u8],
) -> Result {
    let mut at = 0;
    while at < bytes.len() {
        let end = bytes.len().min(at + 3);
        let n = stream.write(&bytes[at..end])?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
        }
        owner.send_bytes_written(send, n)?;
        at += n;
    }
    Ok(())
}
fn streams() -> Result<(UnixStream, UnixStream)> {
    let (a, b) = UnixStream::pair()?;
    for s in [&a, &b] {
        s.set_read_timeout(Some(Duration::from_secs(2)))?;
        s.set_write_timeout(Some(Duration::from_secs(2)))?;
    }
    Ok((a, b))
}
#[test]
fn actual_original_mq_old_and_new_refunds_do_not_alias_after_same_identity_reconnect() -> Result {
    let (mut stream, mut service) = streams()?;
    let worker = std::thread::spawn(move || -> Result<(usize, usize)> {
        let start = frame(&mut service)?;
        assert!(matches!(Request::decode(&start)?, Request::Start(_)));
        let mut sent = emit(&mut service, Response::Connected(PEER))?;
        // Observe the bytes, but defer their processing/refund while independent
        // service notifications cross this original client SEND.
        let old = frame(&mut service)?;
        assert!(
            matches!(Request::decode(&old)?,Request::Send {peer:PEER,message,..} if message==MESSAGE)
        );
        sent += emit(&mut service, Response::Disconnected(PEER))?;
        sent += emit(&mut service, Response::Connected(PEER))?;
        let new = frame(&mut service)?;
        assert!(matches!(
            Request::decode(&new)?,
            Request::Send { peer: PEER, .. }
        ));
        sent += emit(&mut service, Response::SendCredit(PEER))?;
        sent += emit(&mut service, Response::SendCredit(PEER))?;
        Ok((start.len() + old.len() + new.len(), sent))
    });
    let mut instance = Instance::new();
    let mut owner = TransportClient::<2, 4, 8>::new(&mut instance, Start::new(None, true))?;
    let mut bytes = vec![0; 65535];
    let (epoch, n) = owner.begin(&mut bytes)?;
    stream.write_all(&bytes[..n])?;
    let connected = frame(&mut stream)?;
    let Event::Connected(old) = owner.receive(epoch, &connected)? else {
        return Err("missing old peer".into());
    };
    let (old_send, n) = owner.prepare_send(old, 0, &MESSAGE, &mut bytes)?;
    tracked(&mut stream, &mut owner, old_send, &bytes[..n])?;
    assert_eq!(owner.take_send_result(old_send)?, SendOutcome::Written);
    let disconnected = frame(&mut stream)?;
    assert_eq!(
        owner.receive(epoch, &disconnected)?,
        Event::Disconnected(old)
    );
    let connected = frame(&mut stream)?;
    let Event::Connected(new) = owner.receive(epoch, &connected)? else {
        return Err("missing replacement peer".into());
    };
    let (new_send, n) = owner.prepare_send(new, 0, &MESSAGE, &mut bytes)?;
    tracked(&mut stream, &mut owner, new_send, &bytes[..n])?;
    let old_refund = frame(&mut stream)?;
    assert_eq!(
        owner.receive(epoch, &old_refund)?,
        Event::LateSendCredit(PEER)
    );
    assert_eq!(owner.send_credit(new)?, 3);
    let new_refund = frame(&mut stream)?;
    assert_eq!(owner.receive(epoch, &new_refund)?, Event::SendCredit(new));
    assert_eq!(owner.send_credit(new)?, 4);
    assert_eq!(owner.take_send_result(new_send)?, SendOutcome::Written);
    let counts = worker
        .join()
        .map_err(|_| std::io::Error::other("service observer panicked"))??;
    assert_eq!(counts, (136, 200));
    Ok(())
}
#[test]
fn actual_discarded_old_unwritten_frame_needs_no_refund_and_cannot_steal_new_credit() -> Result {
    let (mut stream, mut service) = streams()?;
    let worker = std::thread::spawn(move || -> Result<(usize, usize)> {
        let start = frame(&mut service)?;
        let mut sent = 0;
        for event in [
            Response::Connected(PEER),
            Response::Disconnected(PEER),
            Response::Connected(PEER),
        ] {
            sent += emit(&mut service, event)?;
        }
        let only = frame(&mut service)?;
        assert!(
            matches!(Request::decode(&only)?,Request::Send {peer:PEER,message,..} if message==MESSAGE)
        );
        sent += emit(&mut service, Response::SendCredit(PEER))?;
        Ok((start.len() + only.len(), sent))
    });
    let mut instance = Instance::new();
    let mut owner = TransportClient::<2, 4, 8>::new(&mut instance, Start::new(None, true))?;
    let mut bytes = vec![0; 65535];
    let (epoch, n) = owner.begin(&mut bytes)?;
    stream.write_all(&bytes[..n])?;
    let connected = frame(&mut stream)?;
    let Event::Connected(old) = owner.receive(epoch, &connected)? else {
        return Err("missing old peer".into());
    };
    let (old_send, _) = owner.prepare_send(old, 0, &MESSAGE, &mut bytes)?;
    // This exact wholly unwritten frame is removed from the host FIFO. Its later
    // cancellation callback still must not absorb or manufacture new credit.
    let disconnected = frame(&mut stream)?;
    owner.receive(epoch, &disconnected)?;
    let connected = frame(&mut stream)?;
    let Event::Connected(new) = owner.receive(epoch, &connected)? else {
        return Err("missing new peer".into());
    };
    let (new_send, n) = owner.prepare_send(new, 0, &MESSAGE, &mut bytes)?;
    tracked(&mut stream, &mut owner, new_send, &bytes[..n])?;
    let credit = frame(&mut stream)?;
    assert_eq!(owner.receive(epoch, &credit)?, Event::SendCredit(new));
    assert_eq!(owner.send_credit(new)?, 4);
    owner.cancel_unwritten(old_send)?;
    assert_eq!(owner.send_credit(new)?, 4);
    assert_eq!(
        owner.take_send_result(old_send)?,
        SendOutcome::CancelledUnsent
    );
    assert_eq!(owner.take_send_result(new_send)?, SendOutcome::Written);
    let counts = worker
        .join()
        .map_err(|_| std::io::Error::other("service observer panicked"))??;
    assert_eq!(counts, (88, 160));
    Ok(())
}
