//! Numeric official helper arguments, parsed only after raw resource capture.
use super::{Cause, Failure, failure};
use std::{ffi::OsString, net::Ipv4Addr};
fn next_arg(args: &mut impl Iterator<Item = OsString>, code: u8) -> Result<OsString, Failure> {
    args.next()
        .ok_or_else(|| failure(code, Cause::Usage("missing official helper argument")))
}
fn ipv4(arg: &OsString, code: u8) -> Result<Ipv4Addr, Failure> {
    arg.to_str()
        .filter(|s| s.len() <= 15)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| failure(code, Cause::Usage("expected a numeric IPv4 address")))
}
fn port(arg: &OsString) -> Result<u16, Failure> {
    let port = arg
        .to_str()
        .filter(|s| s.len() <= 16)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|n| *n != 0);
    port.ok_or_else(|| failure(8, Cause::Usage("port must be decimal1..65535")))
}
fn no_more(args: &mut impl Iterator<Item = OsString>, code: u8) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err(failure(code, Cause::Usage("unexpected helper argument")));
    }
    Ok(())
}

pub(crate) struct Client {
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    pub advertised: u16,
}
pub(crate) fn client() -> Result<Client, Failure> {
    let mut args = std::env::args_os();
    let _name = args.next();
    let local = ipv4(&next_arg(&mut args, 6)?, 7)?;
    let remote = ipv4(&next_arg(&mut args, 6)?, 7)?;
    let advertised = port(&next_arg(&mut args, 6)?)?;
    no_more(&mut args, 6)?;
    Ok(Client {
        local,
        remote,
        advertised,
    })
}
pub(crate) fn server() -> Result<Ipv4Addr, Failure> {
    let mut args = std::env::args_os();
    let _name = args.next();
    let local = ipv4(&next_arg(&mut args, 3)?, 4)?;
    no_more(&mut args, 3)?;
    Ok(local)
}
