//! RPS command selection and bounded resource configuration.
use crate::Failure;
use gnunet_rps_client_host::{Limits, Peer, ReplyCountProfile};
use std::time::Duration;
#[derive(Clone, Copy)]
pub(super) enum Selection {
    Sample(usize),
    View(u32),
    Stream,
    Seed(Peer),
}
fn number(bytes: &[u8]) -> Result<usize, Failure> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("RPS count must be a nonnegative decimal integer".into());
    }
    let mut value = 0usize;
    for b in bytes {
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(*b - b'0')))
            .ok_or("RPS count overflow")?;
    }
    Ok(value)
}
impl Selection {
    pub(super) fn read(
        seed: Option<Vec<u8>>,
        view: bool,
        stream: bool,
        args: &[Vec<u8>],
    ) -> Result<Self, Failure> {
        if usize::from(seed.is_some()) + usize::from(view) + usize::from(stream) > 1 {
            return Err("select only one of --seed, --view and --stream".into());
        }
        if seed.is_some() || stream {
            if !args.is_empty() {
                return Err("seed/stream mode accepts no positional count".into());
            }
        } else if args.len() > 1 {
            return Err("RPS accepts at most one positional count".into());
        }
        if let Some(seed) = seed {
            if seed.len() != 52 {
                return Err(
                    "RPS seed requires the full52-character Crockford peer identity".into(),
                );
            }
            let mut cfg = gnunet_config::Configuration::new(Default::default());
            cfg.set_value(b"seed", b"public", Some(&seed))?;
            let mut peer = [0; 32];
            cfg.get_data(b"seed", b"public", &mut peer)?;
            Ok(Self::Seed(peer))
        } else if stream {
            Ok(Self::Stream)
        } else if view {
            Ok(Self::View(
                args.first().map_or(Ok(0), |v| number(v))?.try_into()?,
            ))
        } else {
            Ok(Self::Sample(args.first().map_or(Ok(1), |v| number(v))?))
        }
    }
    pub(super) fn continuous(self) -> bool {
        matches!(self, Self::View(0) | Self::Stream)
    }
}
#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub(super) native: Limits,
    pub(super) total: Duration,
    pub(super) output: Duration,
    pub(super) max_output: usize,
    pub(super) resolver: gnunet_resolver_broker::Limits,
}
fn time(
    c: &gnunet_config::Configuration,
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = if c.have_value(b"rps-client-rust", key) {
        Duration::from_micros(c.get_time(b"rps-client-rust", key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() >= u128::from(u64::MAX)
        || std::time::Instant::now().checked_add(d).is_none()
    {
        return Err("RPS local deadlines must be finite and nonzero".into());
    }
    Ok(d)
}
fn size(c: &gnunet_config::Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(b"rps-client-rust", key) {
        c.get_size(b"rps-client-rust", key)?.try_into()?
    } else {
        default
    })
}
impl Settings {
    pub(super) fn read(
        c: &gnunet_config::Configuration,
        selection: Selection,
    ) -> Result<Self, Failure> {
        let defaults = Limits::default();
        let native = Limits {
            frame_bytes: size(c, b"MAX_FRAME_BYTES", defaults.frame_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", defaults.io_slice_bytes)?,
            max_sample_peers: size(c, b"MAX_SAMPLE_PEERS", defaults.max_sample_peers)?,
            initial_timeout: time(c, b"INITIAL_TIMEOUT", defaults.initial_timeout)?,
            input_timeout: time(c, b"INPUT_TIMEOUT", defaults.input_timeout)?,
            reply_profile: match c.get(b"rps-client-rust", b"REPLY_COUNT_PROFILE") {
                None | Some(b"native") => ReplyCountProfile::native(),
                Some(b"little") => ReplyCountProfile::CNativeLittle,
                Some(b"big") => ReplyCountProfile::CNativeBig,
                _ => return Err("RPS REPLY_COUNT_PROFILE must be native, little or big".into()),
            },
        };
        let max_output = size(c, b"MAX_OUTPUT_BYTES", 4 * 1024 * 1024)?;
        if !(128..=16 * 1024 * 1024).contains(&max_output) || native.max_sample_peers > 65536 {
            return Err("RPS local output/sample resource limit out of range".into());
        }
        if let Selection::Sample(n) = selection
            && (n > native.max_sample_peers || n.checked_mul(53).is_none_or(|n| n > max_output))
        {
            return Err("RPS sample demand exceeds the explicit local budget".into());
        }
        Ok(Self {
            native,
            max_output,
            resolver: Default::default(),
            total: time(
                c,
                b"TOTAL_TIMEOUT",
                Duration::from_secs(if selection.continuous() { 3600 } else { 60 }),
            )?,
            output: time(c, b"OUTPUT_TIMEOUT", Duration::from_secs(10))?,
        })
    }
}
