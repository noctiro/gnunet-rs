//! Actual GNUnet NAT command using shared PROGRAM and real native clients.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _written = writeln!(io::stderr().lock(), "NAT command: {e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native NAT command requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_nat_test_host::cli::{Action, NatOptions};
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut options = Options::new();
    let tcp = Target::new(0i32);
    let udp = Target::new(0i32);
    let section = Target::new(None);
    options.add(helpers::flag(b't', b"tcp", b"use TCP", tcp.clone()));
    options.add(helpers::flag(b'u', b"udp", b"use UDP", udp.clone()));
    options.add(helpers::string(
        b'S',
        b"section",
        b"NAME",
        b"original NAT adapter configuration section",
        section.clone(),
    ));
    let local = Target::new(None);
    let remote = Target::new(None);
    let stun = Target::new(0i32);
    let watch = Target::new(0i32);
    options.add(helpers::string(
        b'i',
        b"in",
        b"ADDRESS",
        b"local literal IP and port",
        local.clone(),
    ));
    options.add(helpers::string(
        b'r',
        b"remote",
        b"ADDRESS",
        b"IPv4 peer to ask for connection reversal",
        remote.clone(),
    ));
    options.add(helpers::flag(
        b's',
        b"stun",
        b"bind actual UDP socket and process original STUN transactions",
        stun.clone(),
    ));
    options.add(helpers::flag(
        b'W',
        b"watch",
        b"observe original reversal notifications",
        watch.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-nat", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-nat",help:Some(b"Actual official NAT client/query/test. Address hints and local sends do not prove connectivity; a received original public challenge is an unauthenticated path observation. TCP/UDP tests require configured section PORT and an actual gnunet-nat-server."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 {
                return Ok(());
            }
            return Err(format!("PROGRAM stopped {:?} code{}", s.reason, s.code).into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("unexpected positional NAT arguments".into());
    }
    let tcp = tcp.get()? != 0;
    let udp = udp.get()? != 0;
    if tcp && udp {
        return Err("TCP and UDP are mutually exclusive".into());
    }
    let protocol = if tcp {
        Some(6)
    } else if udp {
        Some(17)
    } else {
        None
    };
    let protocol = protocol.ok_or("select exactly --tcp or --udp")?;
    let local = local
        .get()?
        .ok_or("--in requires a local literal endpoint")?;
    let local = core::str::from_utf8(&local)?.parse()?;
    let remote = remote
        .get()?
        .map(|raw| -> Result<std::net::SocketAddr, Failure> {
            Ok(core::str::from_utf8(&raw)?.parse()?)
        })
        .transpose()?;
    let action = Action::Nat(NatOptions {
        local,
        remote,
        section: section.get()?.unwrap_or_else(|| b"undefined".to_vec()),
        protocol,
        stun: stun.get()? != 0,
        watch: watch.get()? != 0,
    });
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gnunet_nat_test_host::cli::scheduled(
            prepared, clock, action,
        ))
}
