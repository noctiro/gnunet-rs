//! Official stream/listen/echo modes and independent bounded Rust resources.
use crate::Cause;
use gnunet_cadet_host::inspect::Query;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::time::Duration;
#[derive(Clone, Copy, Debug)]
pub(super) enum Mode {
    Connect([u8; 32]),
    Listen,
}
pub(super) struct Selection {
    port: Target<Option<Vec<u8>>>,
    echo: Target<i32>,
    peers: Target<i32>,
    tunnels: Target<i32>,
    peer: Target<Option<Vec<u8>>>,
    connection: Target<Option<Vec<u8>>>,
}
pub(super) enum Command {
    Stream(Settings),
    Inspect { query: Query, bounds: Bounds },
}
#[derive(Clone, Copy)]
pub(super) struct Bounds {
    pub operation: Duration,
    pub cleanup: Duration,
    pub io_bytes: usize,
}
impl Command {
    pub(super) const fn operation(&self) -> Duration {
        match self {
            Self::Stream(settings) => settings.operation,
            Self::Inspect { bounds, .. } => bounds.operation,
        }
    }
}
pub(super) struct Settings {
    pub mode: Mode,
    pub port: [u8; 64],
    pub echo: bool,
    pub chunk: usize,
    pub operation: Duration,
    pub cleanup: Duration,
    pub io_bytes: usize,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            port: Target::new(None),
            echo: Target::new(0),
            peers: Target::new(0),
            tunnels: Target::new(0),
            peer: Target::new(None),
            connection: Target::new(None),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'o',
            b"open-port",
            b"SHARED_SECRET",
            b"listen for one channel at this port name",
            self.port.clone(),
        ));
        options.add(helpers::flag(
            b'e',
            b"echo",
            b"echo received messages when listening, or measure periodic echoes when connecting",
            self.echo.clone(),
        ));
        options.add(helpers::flag(
            b'P',
            b"peers",
            b"List all known peers",
            self.peers.clone(),
        ));
        options.add(helpers::flag(
            b'T',
            b"tunnels",
            b"List all tunnels",
            self.tunnels.clone(),
        ));
        options.add(helpers::string(
            b'p',
            b"peer",
            b"PEER_ID",
            b"List paths to this peer",
            self.peer.clone(),
        ));
        options.add(helpers::string(
            b'C',
            b"connection",
            b"CONNECTION_ID",
            b"Inspect a connection (unavailable in the official service)",
            self.connection.clone(),
        ));
        options
    }
    pub(super) fn finish(
        self,
        config: &gnunet_config::Configuration,
        args: &[Vec<u8>],
    ) -> Result<Command, Cause> {
        let listening = self.port.get()?;
        let echo = self.echo.get()? != 0;
        let peers = self.peers.get()? != 0;
        let tunnels = self.tunnels.get()? != 0;
        let peer = self.peer.get()?;
        if self.connection.get()?.is_some() {
            return Err(
                "CADET connection inspection is unavailable in the official service".into(),
            );
        }
        let inspections = usize::from(peers) + usize::from(tunnels) + usize::from(peer.is_some());
        if inspections > 1
            || (inspections == 1 && (echo || listening.is_some() || !args.is_empty()))
        {
            return Err("select one CADET inspection without stream arguments".into());
        }
        let bounds = Bounds {
            operation: Duration::from_secs(u64::try_from(number(
                config,
                b"OPERATION_SECONDS",
                30,
                1,
                3600,
            )?)?),
            cleanup: Duration::from_secs(u64::try_from(number(
                config,
                b"CLEANUP_SECONDS",
                5,
                1,
                60,
            )?)?),
            io_bytes: number(config, b"IO_BYTES", 8192, 1, 65535)?,
        };
        let query = if let Some(peer) = peer {
            Some(Query::Paths(peer_identity(&peer)?))
        } else if peers {
            Some(Query::Peers)
        } else if tunnels {
            Some(Query::Tunnels)
        } else {
            None
        };
        if let Some(query) = query {
            return Ok(Command::Inspect { query, bounds });
        }
        let (mode, name) = if let Some(name) = listening {
            if !args.is_empty() {
                return Err("listen mode accepts no target positional arguments".into());
            }
            (Mode::Listen, name)
        } else {
            if args.is_empty() || args.len() > 2 {
                return Err("provide PEER [PORT], or use -o PORT to listen".into());
            }
            (
                Mode::Connect(peer_identity(&args[0])?),
                args.get(1).cloned().unwrap_or_else(|| b"default".to_vec()),
            )
        };
        if name.len() > 4096 || name.contains(&0) {
            return Err("port name exceeds4096bytes or contains NUL".into());
        }
        let port = gnunet_crypto::hash512(&name);
        Ok(Command::Stream(Settings {
            mode,
            port,
            echo,
            chunk: number(config, b"CHUNK_BYTES", 60000, 1, 60000)?,
            operation: bounds.operation,
            cleanup: bounds.cleanup,
            io_bytes: bounds.io_bytes,
        }))
    }
}
fn peer_identity(bytes: &[u8]) -> Result<[u8; 32], Cause> {
    let mut peer = [0; 32];
    if bytes.len() != 52 || gnunet_gnsrecord::decode_base32(bytes, &mut peer)? != peer.len() {
        return Err("PEER must be a 52-character GNUnet peer identity".into());
    }
    Ok(peer)
}
fn number(
    config: &gnunet_config::Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, Cause> {
    let Some(bytes) = config.get(b"cadet-cli", key) else {
        return Ok(default);
    };
    let value: usize = std::str::from_utf8(bytes)?.parse()?;
    if !(min..=max).contains(&value) {
        return Err(format!("out of range [cadet-cli] {}", String::from_utf8_lossy(key)).into());
    }
    Ok(value)
}
