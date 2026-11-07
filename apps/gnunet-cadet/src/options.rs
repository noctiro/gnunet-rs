//! Official stream/listen/echo modes and independent bounded Rust resources.
use crate::Cause;
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
        options
    }
    pub(super) fn finish(
        self,
        config: &gnunet_config::Configuration,
        args: &[Vec<u8>],
    ) -> Result<Settings, Cause> {
        let listening = self.port.get()?;
        let (mode, name) = if let Some(name) = listening {
            if !args.is_empty() {
                return Err("listen mode accepts no target positional arguments".into());
            }
            (Mode::Listen, name)
        } else {
            if args.is_empty() || args.len() > 2 {
                return Err("provide PEER [PORT], or use -o PORT to listen".into());
            }
            let mut peer = [0; 32];
            if args[0].len() != 52
                || gnunet_gnsrecord::decode_base32(&args[0], &mut peer)? != peer.len()
            {
                return Err("PEER must be one official52-character GNUnet peer identity".into());
            }
            (
                Mode::Connect(peer),
                args.get(1).cloned().unwrap_or_else(|| b"default".to_vec()),
            )
        };
        if name.len() > 4096 || name.contains(&0) {
            return Err("port name exceeds4096bytes or contains NUL".into());
        }
        let port = gnunet_crypto::hash512(&name);
        Ok(Settings {
            mode,
            port,
            echo: self.echo.get()? != 0,
            chunk: number(config, b"CHUNK_BYTES", 60000, 1, 60000)?,
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
        })
    }
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
