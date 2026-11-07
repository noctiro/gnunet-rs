//! Actual Linux Rust privileged DNS interception helper; no C helper wrapper.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-helper-dns: {e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn Error>> {
    Err("official DNS interception helper platform is Linux".into())
}
#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).take(7).collect::<Vec<_>>();
    let args = args
        .iter()
        .map(|value| {
            value
                .to_str()
                .filter(|v| v.len() <= 128)
                .ok_or("DNS helper argument must be bounded UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args.len() != 6 {
        return Err("DNS helper requires exactly IFNAME IPV6ADDR IPV6PREFIX IPV4ADDR IPV4MASK SKIP_ROUTING_SETUP".into());
    }
    let skip_routing = match args[5] {
        "0" => false,
        "1" => true,
        _ => return Err("DNS helper skip-routing flag must be exactly0 or1".into()),
    };
    let options = gnunet_dns_service_host::platform::Options {
        interface: args[0].to_owned(),
        ipv6: args[1].parse()?,
        prefix: args[2].parse()?,
        ipv4: args[3].parse()?,
        mask: args[4].parse()?,
        skip_routing,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gnunet_dns_service_host::platform::run(options))?;
    Ok(())
}
