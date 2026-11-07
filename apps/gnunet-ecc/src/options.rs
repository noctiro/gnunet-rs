use crate::Failure;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, time::Duration};

pub(super) struct Arguments {
    examples: Target<i32>,
    iterate: Target<i32>,
    end: Target<u32>,
    generate: Target<u32>,
    public: Target<i32>,
    private: Target<i32>,
    hex: Target<i32>,
    timeout: Target<u64>,
    attempts: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            examples: Target::new(0),
            iterate: Target::new(0),
            end: Target::new(u32::MAX),
            generate: Target::new(0),
            public: Target::new(0),
            private: Target::new(0),
            hex: Target::new(0),
            timeout: Target::new(0),
            attempts: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        for (short, long, help, target) in [
            (
                b'E',
                b"examples".as_slice(),
                b"Print real ECDHE examples, explicitly including private material".as_slice(),
                &self.examples,
            ),
            (
                b'i',
                b"iterate".as_slice(),
                b"List original raw32 key-file public identities on stderr".as_slice(),
                &self.iterate,
            ),
            (
                b'p',
                b"print-public-key".as_slice(),
                b"Print each original Ed25519 public key in Base32".as_slice(),
                &self.public,
            ),
            (
                b'P',
                b"print-private-key".as_slice(),
                b"Explicitly print each original private seed in Base32".as_slice(),
                &self.private,
            ),
            (
                b'x',
                b"print-hex".as_slice(),
                b"Print each public key as HEX:: followed by lowercase hex".as_slice(),
                &self.hex,
            ),
        ] {
            o.add(helpers::flag(short, long, help, target.clone()));
        }
        o.add(helpers::uint(
            b'e',
            b"end",
            b"COUNT",
            b"Maximum original records listed with -i (default UINT32_MAX)",
            self.end.clone(),
        ));
        o.add(helpers::uint(
            b'g',
            b"generate-keys",
            b"COUNT",
            b"Generate COUNT raw32 seeds; optional positional vanity prefix",
            self.generate.clone(),
        ));
        o.add(helpers::relative_time(
            0,
            b"timeout",
            b"DURATION",
            b"Optional original whole operation bound; zero uses configuration",
            self.timeout.clone(),
        ));
        o.add(helpers::ulong(
            0,
            b"max-attempts",
            b"COUNT",
            b"Optional total candidate bound; zero uses configuration",
            self.attempts.clone(),
        ));
        o
    }
    pub fn select(&self, c: &Configuration, args: &[Vec<u8>]) -> Result<Settings, Failure> {
        let configured = |name: &[u8]| -> Result<u64, Failure> {
            Ok(c.get(b"ecc-rust", name)
                .map(|_| c.get_number(b"ecc-rust", name))
                .transpose()?
                .unwrap_or(0))
        };
        let timeout = self.timeout.get()?;
        let timeout = if timeout == 0 {
            c.get(b"ecc-rust", b"TOTAL_TIMEOUT")
                .map(|_| c.get_time(b"ecc-rust", b"TOTAL_TIMEOUT"))
                .transpose()?
                .unwrap_or(0)
        } else {
            timeout
        };
        let lifetime = (timeout != 0).then_some(Duration::from_micros(timeout));
        if lifetime.is_some_and(|d| std::time::Instant::now().checked_add(d).is_none()) {
            return Err("ECC original native timeout cannot be represented".into());
        }
        let attempts = self.attempts.get()?;
        let attempts = if attempts == 0 {
            configured(b"MAX_ATTEMPTS")?
        } else {
            attempts
        };
        let work = c
            .get(b"ecc-rust", b"WORK_UNITS")
            .map(|_| c.get_number(b"ecc-rust", b"WORK_UNITS"))
            .transpose()?
            .unwrap_or(32);
        if !(1..=65536).contains(&work) {
            return Err("ECC WORK_UNITS must be 1..=65536".into());
        }
        let operation = if self.examples.get()? != 0 {
            // C examples take precedence and do not open a positional key file.
            Operation::Examples
        } else {
            let path = args
                .first()
                .ok_or("ECC operation requires an explicit key filename")?;
            if path.is_empty() || path.len() > 4096 || path.contains(&0) {
                return Err("invalid ECC key filename".into());
            }
            let path = PathBuf::from(OsString::from_vec(path.clone()));
            if self.iterate.get()? != 0 {
                if args.len() != 1 {
                    return Err("ECC -i accepts exactly one key filename".into());
                }
                Operation::Iterate {
                    path,
                    maximum: self.end.get()?,
                }
            } else if self.generate.get()? > 0 {
                if args.len() > 2 {
                    return Err("ECC -g accepts a filename and optional vanity prefix".into());
                }
                let vanity = args
                    .get(1)
                    .map(|v| crate::keys::Vanity::new(v))
                    .transpose()?;
                Operation::Generate {
                    path,
                    count: self.generate.get()?,
                    vanity,
                }
            } else {
                if args.len() != 1 {
                    return Err("ECC print accepts exactly one key filename".into());
                }
                let form = if self.hex.get()? != 0 {
                    Print::Hex
                } else if self.public.get()? != 0 {
                    Print::Public
                } else if self.private.get()? != 0 {
                    Print::Private
                } else {
                    return Err(
                        "select -E, -i, -g COUNT, -x, -p or -P; no implicit key creation".into(),
                    );
                };
                Operation::Print { path, form }
            }
        };
        Ok(Settings {
            operation,
            lifetime,
            max_attempts: (attempts != 0).then_some(attempts),
            work_units: usize::try_from(work)?,
        })
    }
}
#[derive(Clone, Copy)]
pub(super) enum Print {
    Public,
    Private,
    Hex,
}
pub(super) enum Operation {
    Examples,
    Iterate {
        path: PathBuf,
        maximum: u32,
    },
    Generate {
        path: PathBuf,
        count: u32,
        vanity: Option<crate::keys::Vanity>,
    },
    Print {
        path: PathBuf,
        form: Print,
    },
}
pub(super) struct Settings {
    pub operation: Operation,
    pub lifetime: Option<Duration>,
    pub max_attempts: Option<u64>,
    pub work_units: usize,
}
