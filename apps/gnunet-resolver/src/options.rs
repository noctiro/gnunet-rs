//! Standard reverse flag and one original bounded lookup argument.
use crate::Cause;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::net::IpAddr;
pub(super) enum Request {
    Forward(Vec<u8>),
    Reverse(IpAddr),
}
pub(super) struct Settings {
    pub request: Request,
    pub maximum_results: usize,
    pub maximum_output_bytes: usize,
}
pub(super) struct Selection {
    reverse: Target<i32>,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            reverse: Target::new(0),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::flag(
            b'r',
            b"reverse",
            b"perform a reverse IP-to-hostname lookup",
            self.reverse.clone(),
        ));
        options
    }
    pub(super) fn finish(
        self,
        config: &gnunet_config::Configuration,
        args: &[Vec<u8>],
    ) -> Result<Option<Settings>, Cause> {
        if args.is_empty() {
            return Ok(None);
        }
        if args.len() != 1 {
            return Err("one hostname or numeric reverse address is required".into());
        }
        let request = if self.reverse.get()? != 0 {
            Request::Reverse(std::str::from_utf8(&args[0])?.parse()?)
        } else {
            if args[0].is_empty() || args[0].len() > 1024 || args[0].contains(&0) {
                return Err("invalid bounded forward hostname".into());
            }
            Request::Forward(args[0].clone())
        };
        Ok(Some(Settings {
            request,
            maximum_results: number(config, b"MAX_RESULTS", 4096, 1, 65536)?,
            maximum_output_bytes: number(
                config,
                b"MAX_OUTPUT_BYTES",
                16 * 1024 * 1024,
                1,
                64 * 1024 * 1024,
            )?,
        }))
    }
}
fn number(
    config: &gnunet_config::Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, Cause> {
    let Some(value) = config.get(b"resolver-cli", key) else {
        return Ok(default);
    };
    let value: usize = std::str::from_utf8(value)?.parse()?;
    if !(min..=max).contains(&value) {
        return Err(format!(
            "out of range [resolver-cli] {}",
            String::from_utf8_lossy(key)
        )
        .into());
    }
    Ok(value)
}
