//! Official proxy options; -6 retains the official long-option spelling.
use crate::Cause;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
};
use std::{error::Error, fmt, path::PathBuf, rc::Rc};

#[derive(Debug)]
struct FilenameFailure(Rc<gnunet_config::Error>);
impl fmt::Display for FilenameFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl Error for FilenameFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) struct Selection {
    port: Target<u16>,
    authority: Target<Filename>,
    disable_ipv6: Target<i32>,
}
pub(super) struct Chosen {
    pub port: u16,
    pub authority: Option<PathBuf>,
    pub disable_ipv6: bool,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            port: Target::new(7777),
            authority: Target::new(Filename {
                path: None,
                error: None,
            }),
            disable_ipv6: Target::new(0),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::uint16(
            b'p',
            b"port",
            b"PORT",
            b"Listen on this SOCKS5 port (default 7777)",
            self.port.clone(),
        ));
        options.add(helpers::filename(
            b'a',
            b"authority",
            b"PEM",
            b"Existing combined CA certificate and signing-key PEM",
            self.authority.clone(),
        ));
        options.add(helpers::flag(
            b'6',
            b"disable-ivp6",
            b"Disable IPv6 (official option spelling)",
            self.disable_ipv6.clone(),
        ));
        options
    }
    pub(super) fn finish(self, args: &[Vec<u8>]) -> Result<Chosen, Cause> {
        if !args.is_empty() {
            return Err("gnunet-gns-proxy accepts no positional arguments".into());
        }
        let authority = self.authority.get()?;
        if let Some(error) = authority.error {
            return Err(Box::new(FilenameFailure(error)));
        }
        Ok(Chosen {
            port: self.port.get()?,
            authority: authority.path,
            disable_ipv6: self.disable_ipv6.get()? != 0,
        })
    }
}
