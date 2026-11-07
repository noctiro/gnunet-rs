//! Real Unix stream framing, connection isolation, FIFO and host drop regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol and real resource regressions assert independent expected outcomes"
)]
#![cfg(unix)]
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service};
use gnunet_pils_host::{Host, Limits};
use gnunet_wire::official::{
    MessageHeader, MessageType, SignaturePurpose,
    pils::{PeerUpdate, Request, Response},
};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("entropy"))?;
        let path = std::env::temp_dir().join(format!("gp-{:016x}", u64::from_be_bytes(random)));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
fn host(scratch: &Scratch) -> Result<Host, Box<dyn std::error::Error>> {
    let listener = UnixListener::bind(scratch.0.join("socket"))?;
    let service = Service::new(
        MasterKey::from_seed([7; 32]),
        Profile::Reference029,
        100,
        HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 2048,
            maximum_addresses: 32,
        },
    )?;
    Ok(Host::new(
        listener,
        service,
        Limits {
            clients: 4,
            receive_bytes: 65535,
            transmit_bytes: 262140,
            accepts_per_step: 4,
            address_bytes: 2048,
        },
    )?)
}
fn connect(scratch: &Scratch) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(scratch.0.join("socket"))?;
    stream.set_nonblocking(true)?;
    Ok(stream)
}
fn receive(
    host: &mut Host,
    stream: &mut UnixStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for _ in 0..256 {
        host.poll_once(100)?;
        let missing = if bytes.len() < 4 {
            4 - bytes.len()
        } else {
            MessageHeader::decode(&bytes[..4])?.size() - bytes.len()
        };
        if missing == 0 {
            return Ok(bytes);
        }
        let mut scratch = [0; 4096];
        let n = missing.min(scratch.len());
        match stream.read(&mut scratch[..n]) {
            Ok(0) => return Err("unexpected EOF".into()),
            Ok(n) => bytes.extend_from_slice(&scratch[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("bounded host receive made no progress".into())
}
#[test]
fn fragmented_original_signature_reply_never_reaches_another_client()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let mut host = host(&scratch)?;
    let mut a = connect(&scratch)?;
    let mut b = connect(&scratch)?;
    PeerUpdate::decode(&receive(&mut host, &mut a)?)?;
    PeerUpdate::decode(&receive(&mut host, &mut b)?)?;
    let mut region = [0x41; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut region)?;
    let mut request = [0; 56];
    Request::Sign {
        request: 0x11223344,
        region: &region,
    }
    .encode(&mut request)?;
    a.write_all(&request[..3])?;
    assert_eq!(host.poll_once(100)?.requests, 0);
    a.write_all(&request[3..])?;
    assert!(matches!(
        Response::decode(&receive(&mut host, &mut a)?)?,
        Response::Signature {
            request: 0x11223344,
            ..
        }
    ));
    assert_eq!(
        b.read(&mut [0; 1]).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(host.clients(), 2);
    drop(host);
    assert_eq!(a.read(&mut [0; 1])?, 0);
    assert_eq!(b.read(&mut [0; 1])?, 0);
    Ok(())
}
#[test]
fn malformed_client_closes_independently_of_an_original_live_request()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let mut host = host(&scratch)?;
    let mut a = connect(&scratch)?;
    let mut b = connect(&scratch)?;
    receive(&mut host, &mut a)?;
    receive(&mut host, &mut b)?;
    let mut bad = [0; 4];
    MessageHeader::from_total_size(MessageType::new(1), 4)?.encode(&mut bad)?;
    a.write_all(&bad)?;
    let mut region = [0; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut region)?;
    let mut request = [0; 56];
    Request::Sign {
        request: 2,
        region: &region,
    }
    .encode(&mut request)?;
    b.write_all(&request)?;
    assert!(matches!(
        Response::decode(&receive(&mut host, &mut b)?)?,
        Response::Signature { request: 2, .. }
    ));
    assert_eq!(host.clients(), 1);
    assert_eq!(a.read(&mut [0; 1])?, 0);
    Ok(())
}
#[test]
fn same_connection_sign_and_feed_outputs_preserve_original_fifo()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let mut host = host(&scratch)?;
    let mut a = connect(&scratch)?;
    receive(&mut host, &mut a)?;
    let mut region = [0; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut region)?;
    let mut request = [0; 56];
    Request::Sign {
        request: 4,
        region: &region,
    }
    .encode(&mut request)?;
    let mut feed = [0; 112];
    Request::Feed { block: &[0; 104] }.encode(&mut feed)?;
    let mut compound = request.to_vec();
    compound.extend_from_slice(&feed);
    a.write_all(&compound)?;
    assert!(matches!(
        Response::decode(&receive(&mut host, &mut a)?)?,
        Response::Signature { request: 4, .. }
    ));
    PeerUpdate::decode(&receive(&mut host, &mut a)?)?;
    Ok(())
}
