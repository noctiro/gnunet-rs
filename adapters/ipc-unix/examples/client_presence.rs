//! Actual public service-presence operation; prints only its official tri-state.
use gnunet_client_host::presence::{ServicePresence, test};
use gnunet_config::Configuration;
use std::{
    error::Error,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().ok_or("configuration required")?;
    let service = arguments.next().ok_or("service required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut config = Configuration::default();
    config.parse(path)?;
    let result = match test(&config, service.as_bytes()) {
        Ok(ServicePresence::LikelyUp) => 1,
        Ok(ServicePresence::Down) => 0,
        Err(_) => -1,
    };
    writeln!(io::stdout().lock(), "{result}")?;
    Ok(())
}
