use super::HandshakeData;
use crate::{
    credentials::Tls,
    local_keys,
    tls::{self, Profile},
};
use gnunet_tls_crypto_host::certificate::P256Key;
use quinn_proto::{Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, Event, Transmit};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

type TestResult<T> = Result<T, Box<dyn Error>>;
type Datagram = (Transmit, Vec<u8>);

struct Peer {
    endpoint: Endpoint,
    address: SocketAddr,
    connection: Option<(ConnectionHandle, Connection)>,
    sent_retry: bool,
}

impl Peer {
    fn new(config: Option<quinn::ServerConfig>, port: u16) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::new(
                Arc::new(local_keys::endpoint_config()?),
                config.map(Arc::new),
                false,
                None,
            ),
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            connection: None,
            sent_retry: false,
        })
    }

    fn transmit(&mut self, now: Instant) -> Option<Datagram> {
        let (handle, connection) = self.connection.as_mut()?;
        if connection
            .poll_timeout()
            .is_some_and(|timeout| timeout <= now)
        {
            connection.handle_timeout(now);
        }
        while let Some(event) = connection.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(*handle, event) {
                connection.handle_event(event);
            }
        }
        let mut bytes = Vec::new();
        let transmit = connection.poll_transmit(now, 1, &mut bytes)?;
        Some((transmit, bytes))
    }

    fn receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        (transmit, bytes): Datagram,
    ) -> TestResult<Option<Datagram>> {
        if transmit.destination != self.address || transmit.size != bytes.len() {
            return Err(io::Error::other("unexpected in-memory QUIC datagram").into());
        }
        let mut response = Vec::new();
        match self.endpoint.handle(
            now,
            source,
            Some(self.address.ip()),
            transmit.ecn,
            bytes.as_slice().into(),
            &mut response,
        ) {
            Some(DatagramEvent::Response(transmit)) => Ok(Some((transmit, response))),
            Some(DatagramEvent::NewConnection(incoming)) => {
                if !incoming.remote_address_validated() && !self.sent_retry {
                    let transmit = self.endpoint.retry(incoming, &mut response)?;
                    self.sent_retry = true;
                    return Ok(Some((transmit, response)));
                }
                if !incoming.remote_address_validated() || self.connection.is_some() {
                    self.endpoint.ignore(incoming);
                    return Err(io::Error::other(
                        "QUIC Retry did not validate exactly one attempt",
                    )
                    .into());
                }
                self.connection = Some(
                    self.endpoint
                        .accept(incoming, now, &mut response, None)
                        .map_err(|error| error.cause)?,
                );
                Ok(None)
            }
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                let (_, connection) = self
                    .connection
                    .as_mut()
                    .filter(|(key, _)| *key == handle)
                    .ok_or_else(|| {
                        io::Error::other("QUIC datagram addressed another connection")
                    })?;
                connection.handle_event(event);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn connected(&mut self) -> TestResult<bool> {
        let Some((_, connection)) = self.connection.as_mut() else {
            return Ok(false);
        };
        while let Some(event) = connection.poll() {
            if let Event::ConnectionLost { reason } = event {
                return Err(reason.into());
            }
        }
        Ok(!connection.is_handshaking())
    }

    fn connection(&mut self) -> io::Result<&mut Connection> {
        self.connection
            .as_mut()
            .map(|(_, connection)| connection)
            .ok_or_else(|| io::Error::other("missing in-memory QUIC connection"))
    }
}

fn deliver(sender: &mut Peer, receiver: &mut Peer, now: Instant) -> TestResult<()> {
    if let Some(datagram) = sender.transmit(now)
        && let Some(response) = receiver.receive(now, sender.address, datagram)?
        && sender.receive(now, receiver.address, response)?.is_some()
    {
        return Err(io::Error::other("unexpected chained endpoint response").into());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert exact application bytes and negotiated ALPN"
)]
fn native_bridge_handshake_retry_and_stream() -> TestResult<()> {
    let provider = gnunet_tls_crypto_host::provider();
    let key = P256Key::generate()?;
    let certificate = key.self_signed(vec!["gnunet".to_owned()])?;
    let encoded = key.pkcs8()?;
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(encoded.as_bytes().to_vec()));
    let client = tls::client(Arc::clone(&provider), Profile::Raw)?;
    let server = tls::server(
        provider,
        vec![certificate.der().clone()],
        private,
        Profile::Raw,
    )?;
    let config = Tls::from_configs(client, server, Profile::Raw)?;
    let mut client = Peer::new(None, 9000)?;
    let mut server = Peer::new(Some(config.server), 9001)?;
    let mut now = Instant::now();
    client.connection = Some(client.endpoint.connect(
        now,
        config.client,
        server.address,
        "gnunet",
    )?);

    for _ in 0..128 {
        deliver(&mut client, &mut server, now)?;
        deliver(&mut server, &mut client, now)?;
        if client.connected()? && server.connected()? {
            break;
        }
        now += Duration::from_millis(5);
    }
    assert!(client.connected()? && server.connected()? && server.sent_retry);
    for peer in [&mut client, &mut server] {
        let handshake = peer
            .connection()?
            .crypto_session()
            .handshake_data()
            .and_then(|data| data.downcast::<HandshakeData>().ok());
        assert_eq!(
            handshake.as_ref().and_then(|data| data.protocol.as_deref()),
            Some(b"hq-interop".as_slice())
        );
    }

    let message = b"GNUnet QUIC";
    let connection = client.connection()?;
    let stream = connection
        .streams()
        .open(Dir::Uni)
        .ok_or_else(|| io::Error::other("no QUIC stream credit"))?;
    let mut send = connection.send_stream(stream);
    assert_eq!(send.write(message)?, message.len());
    send.finish()?;
    for _ in 0..128 {
        deliver(&mut client, &mut server, now)?;
        deliver(&mut server, &mut client, now)?;
        let connection = server.connection()?;
        if let Some(accepted) = connection.streams().accept(Dir::Uni) {
            assert_eq!(accepted, stream);
            let mut recv = connection.recv_stream(accepted);
            let mut chunks = recv.read(true)?;
            let chunk = chunks
                .next(message.len())?
                .ok_or_else(|| io::Error::other("missing QUIC stream payload"))?;
            assert_eq!(chunk.bytes.as_ref(), message);
            assert!(chunks.next(1)?.is_none());
            let _flow_control = chunks.finalize();
            return Ok(());
        }
        now += Duration::from_millis(5);
    }
    Err(io::Error::other("QUIC stream did not arrive").into())
}
