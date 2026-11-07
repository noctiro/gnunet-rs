use crate::{Cause, Mode};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};

pub(super) struct Settings {
    pub mode: Mode,
    pub key: Option<[u8; 64]>,
    pub payload: Option<Vec<u8>>,
    pub block_type: u32,
    pub replication: u32,
    pub route: u32,
    pub timeout: u64,
    pub expiration: u64,
    pub verbose: bool,
}
pub(super) struct Selection {
    mode: Mode,
    key: Target<Option<Vec<u8>>>,
    data: Target<Option<Vec<u8>>>,
    raw: Target<i32>,
    record: Target<i32>,
    demultiplex: Target<i32>,
    block_type: Target<u32>,
    replication: Target<u32>,
    timeout: Target<u64>,
    expiration: Target<u64>,
    verbose: Target<u32>,
}
fn raw_key(text: &[u8]) -> Result<[u8; 64], Cause> {
    if text.len() != 103 {
        return Err("raw DHT key must contain exactly 103 Base32 digits".into());
    }
    let mut key = [0; 64];
    if gnunet_gnsrecord::decode_base32(text, &mut key)? != 64 {
        return Err("invalid Base32 DHT key".into());
    }
    Ok(key)
}
impl Selection {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            key: Target::new(None),
            data: Target::new(None),
            raw: Target::new(0),
            record: Target::new(0),
            demultiplex: Target::new(0),
            block_type: Target::new(8),
            replication: Target::new(5),
            timeout: Target::new(if mode == Mode::Hello {
                u64::MAX
            } else {
                60_000_000
            }),
            expiration: Target::new(3_600_000_000),
            verbose: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        if self.mode != Mode::Hello {
            o.add(helpers::string(
                b'k',
                b"key",
                b"KEY",
                b"Query key; monitor first attempts Base32 before hashing",
                self.key.clone(),
            ));
            o.add(helpers::flag(
                b'K',
                b"raw-key",
                b"Require -k to contain the printed Base32 key",
                self.raw.clone(),
            ));
            o.add(helpers::uint(
                b't',
                b"type",
                b"TYPE",
                b"Block type, default TEST (8)",
                self.block_type.clone(),
            ));
        }
        if matches!(self.mode, Mode::Get | Mode::Put) {
            o.add(helpers::uint(
                b'r',
                b"replication",
                b"LEVEL",
                b"Requested replication, default 5",
                self.replication.clone(),
            ));
            o.add(helpers::flag(
                b'R',
                b"record",
                b"Record the route",
                self.record.clone(),
            ));
            o.add(helpers::flag(
                b'x',
                b"demultiplex",
                b"Demultiplex at every peer",
                self.demultiplex.clone(),
            ));
        }
        o.add(helpers::relative_time(
            b'T',
            b"timeout",
            b"TIMEOUT",
            b"Total wait; HELLO defaults to forever, others to 60 s",
            self.timeout.clone(),
        ));
        o.add(helpers::verbose(self.verbose.clone()));
        if self.mode == Mode::Put {
            o.add(helpers::string(
                b'd',
                b"data",
                b"DATA",
                b"Nonempty block bytes",
                self.data.clone(),
            ));
            o.add(helpers::relative_time(
                b'e',
                b"expiration",
                b"EXPIRATION",
                b"Record lifetime, default 1 h",
                self.expiration.clone(),
            ));
        }
        o
    }
    pub fn finish(self, args: &[Vec<u8>]) -> Result<Settings, Cause> {
        if (self.mode == Mode::Hello && args.len() > 1)
            || (self.mode != Mode::Hello && !args.is_empty())
        {
            return Err("only gnunet-dht-hello accepts one positional HELLO URL".into());
        }
        let key = match self.key.get()? {
            None if matches!(self.mode, Mode::Get | Mode::Put) => {
                return Err("-k/--key is required".into());
            }
            None => None,
            Some(text) => {
                if text.contains(&0) {
                    return Err("query key contains NUL".into());
                }
                Some(if self.raw.get()? != 0 {
                    raw_key(&text)?
                } else if self.mode == Mode::Monitor {
                    raw_key(&text).unwrap_or_else(|_| gnunet_crypto::hash512(&text))
                } else {
                    gnunet_crypto::hash512(&text)
                })
            }
        };
        let payload = if self.mode == Mode::Hello {
            args.first().cloned()
        } else {
            self.data.get()?
        };
        if self.mode == Mode::Put
            && payload
                .as_ref()
                .is_none_or(|p| p.is_empty() || p.len() > 65535 - 88 || p.contains(&0))
        {
            return Err(
                "PUT requires nonempty NUL-free DATA fitting an official 65535-byte IPC frame"
                    .into(),
            );
        }
        if self.mode == Mode::Hello
            && payload
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 65530 || p.contains(&0))
        {
            return Err("HELLO URL must be nonempty and fit an official IPC frame".into());
        }
        let kind = self.block_type.get()?;
        Ok(Settings {
            mode: self.mode,
            key,
            payload,
            block_type: if kind == 0 { 8 } else { kind },
            replication: self.replication.get()?,
            route: u32::from(self.demultiplex.get()? != 0)
                | (u32::from(self.record.get()? != 0) << 1),
            timeout: self.timeout.get()?,
            expiration: self.expiration.get()?,
            verbose: self.verbose.get()? != 0,
        })
    }
}
