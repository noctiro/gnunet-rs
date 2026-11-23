//! Bind Quinn's crypto interfaces to explicitly configured Rustls QUIC sessions.
mod keys;
mod retry;
#[cfg(test)]
mod tests;

use quinn::{
    ConnectError, ConnectionId, Side, TransportErrorCode,
    crypto::{self, ExportKeyingMaterialError, KeyPair, Keys, UnsupportedVersion},
};
use quinn_proto::{TransportError, transport_parameters::TransportParameters};
use rustls::{
    CipherSuite,
    pki_types::ServerName,
    quic::{self, Connection, KeyChange, Secrets, Suite},
};
use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

/// Negotiated application protocol published after Rustls processes the handshake.
pub(super) struct HandshakeData {
    pub(super) protocol: Option<Vec<u8>>,
}

pub(super) struct Client {
    config: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl Client {
    pub(super) fn new(config: rustls::ClientConfig) -> Result<Self, rustls::Error> {
        let initial = initial_suite(config.crypto_provider())?;
        let config = Arc::new(config);
        // Check TLS 1.3 and QUIC configuration while rustls errors can be reported.
        quic::ClientConnection::new(
            Arc::clone(&config),
            quic::Version::V1,
            IpAddr::V4(Ipv4Addr::LOCALHOST).into(),
            Vec::new(),
        )?;
        Ok(Self { config, initial })
    }
}

impl crypto::ClientConfig for Client {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        parameters: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let wire = retry::Version::try_from(version)?;
        let name = ServerName::try_from(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.to_owned()))?
            .to_owned();
        let connection = quic::ClientConnection::new(
            Arc::clone(&self.config),
            wire.tls_version(),
            name,
            encode(parameters),
        );
        let connection = connection
            .map(Connection::Client)
            .map_err(|_| ConnectError::EndpointStopping)?;
        Ok(Box::new(Session::new(wire, self.initial, Ok(connection))))
    }
}

pub(super) struct Server {
    config: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl Server {
    pub(super) fn new(config: rustls::ServerConfig) -> Result<Self, rustls::Error> {
        let initial = initial_suite(config.crypto_provider())?;
        let config = Arc::new(config);
        // Rustls validates server protocol and early-data policy through this constructor.
        quic::ServerConnection::new(Arc::clone(&config), quic::Version::V1, Vec::new())?;
        Ok(Self { config, initial })
    }
}

impl crypto::ServerConfig for Server {
    fn initial_keys(
        &self,
        version: u32,
        destination: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let wire = retry::Version::try_from(version)?;
        Ok(initial_keys(self.initial, wire, destination, Side::Server))
    }

    #[expect(
        clippy::expect_used,
        reason = "Quinn calls this only after initial_keys accepts the wire version"
    )]
    fn retry_tag(&self, version: u32, destination: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let wire = retry::Version::try_from(version).expect("admitted QUIC version");
        wire.seal(destination, packet)
    }

    #[expect(
        clippy::expect_used,
        reason = "Quinn calls this only after initial_keys accepts the wire version"
    )]
    fn start_session(
        self: Arc<Self>,
        version: u32,
        parameters: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let wire = retry::Version::try_from(version).expect("admitted QUIC version");
        let connection = quic::ServerConnection::new(
            Arc::clone(&self.config),
            wire.tls_version(),
            encode(parameters),
        )
        .map(Connection::Server);
        Box::new(Session::new(wire, self.initial, connection))
    }
}

struct Session {
    wire: retry::Version,
    initial: Suite,
    tls: Result<Connection, rustls::Error>,
    published: bool,
    next_keys: Option<Secrets>,
}

impl Session {
    const fn new(
        wire: retry::Version,
        initial: Suite,
        tls: Result<Connection, rustls::Error>,
    ) -> Self {
        Self {
            wire,
            initial,
            tls,
            published: false,
            next_keys: None,
        }
    }
}

impl crypto::Session for Session {
    fn initial_keys(&self, destination: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.initial, self.wire, destination, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let tls = self.tls.as_ref().ok().filter(|_| self.published)?;
        Some(Box::new(HandshakeData {
            protocol: tls.alpn_protocol().map(<[u8]>::to_vec),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        let certificates = self.tls.as_ref().ok()?.peer_certificates()?;
        Some(Box::new(certificates.to_vec()))
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        matches!(&self.tls, Ok(Connection::Client(_))).then_some(false)
    }

    fn is_handshaking(&self) -> bool {
        self.tls.as_ref().map_or(true, |tls| tls.is_handshaking())
    }

    fn read_handshake(&mut self, data: &[u8]) -> Result<bool, TransportError> {
        let tls = self
            .tls
            .as_mut()
            .map_err(|error| transport_error(TransportErrorCode::INTERNAL_ERROR, error))?;
        tls.read_hs(data).map_err(|error| {
            let code = tls
                .alert()
                .map_or(TransportErrorCode::PROTOCOL_VIOLATION, |alert| {
                    TransportErrorCode::crypto(alert.into())
                });
            transport_error(code, &error)
        })?;
        let observed_sni =
            matches!(tls, Connection::Server(server) if server.server_name().is_some());
        let ready = tls.alpn_protocol().is_some() || observed_sni || !tls.is_handshaking();
        let publish = ready && !self.published;
        self.published |= ready;
        Ok(publish)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let Ok(tls) = &self.tls else {
            return Ok(None);
        };
        let Some(mut bytes) = tls.quic_transport_parameters() else {
            return Ok(None);
        };
        let side = match tls {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        };
        TransportParameters::read(side, &mut bytes)
            .map(Some)
            .map_err(TransportError::from)
    }

    fn write_handshake(&mut self, bytes: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.tls.as_mut().ok()?.write_hs(bytes)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_keys = Some(next);
                keys
            }
        };
        Some(keys::adapt(keys))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let keys = self.next_keys.as_mut()?.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys::Packet(keys.local)),
            remote: Box::new(keys::Packet(keys.remote)),
        })
    }

    fn is_valid_retry(&self, destination: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.wire.verify(destination, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.tls
            .as_ref()
            .map_err(|_| ExportKeyingMaterialError)?
            .export_keying_material(output, label, Some(context))
            .map(|_| ())
            .map_err(|_| ExportKeyingMaterialError)
    }
}

fn initial_suite(provider: &rustls::crypto::CryptoProvider) -> Result<Suite, rustls::Error> {
    provider
        .cipher_suites
        .iter()
        .find_map(|candidate| {
            let suite = candidate.tls13()?;
            if candidate.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256 {
                return None;
            }
            suite.quic_suite()
        })
        .ok_or_else(|| {
            rustls::Error::General("QUIC requires an AES-128-GCM-SHA256 Initial suite".into())
        })
}

fn initial_keys(
    suite: Suite,
    version: retry::Version,
    destination: &ConnectionId,
    side: Side,
) -> Keys {
    let side = match side {
        Side::Client => rustls::Side::Client,
        Side::Server => rustls::Side::Server,
    };
    keys::adapt(suite.keys(destination, side, version.tls_version()))
}

fn encode(parameters: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    parameters.write(&mut bytes);
    bytes
}

fn transport_error(code: TransportErrorCode, error: &rustls::Error) -> TransportError {
    TransportError {
        code,
        frame: None,
        reason: error.to_string(),
    }
}
