//! PROGRAM option preparation for native DNS client tools.
use crate::{Action, packet};
use gnunet_dns_client_host::{self as dns, ipc};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use gnunet_service_startup::ParentControl;
use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
type Failure = Box<dyn Error>;
pub(super) struct Settings {
    pub(super) action: Action,
    pub(super) flags: u32,
    pub(super) ipv4: Option<Ipv4Addr>,
    pub(super) ipv6: Option<Ipv6Addr>,
    pub(super) duration: Duration,
    pub(super) packets: u32,
    pub(super) verbosity: u32,
    pub(super) limits: dns::Limits,
    pub(super) bounds: packet::Bounds,
    pub(super) socket: Option<std::path::PathBuf>,
}
/// Actual utility PROGRAM invocation. It creates no TUN/helper/firewall rule and
/// uses only the admitted DNS interception service client and shared Resolver.
pub fn run(action: Action, parent: Option<ParentControl>) -> Result<(), Failure> {
    let inbound = Target::new(0i32);
    let outbound = Target::new(0i32);
    let ipv4 = Target::new(None);
    let ipv6 = Target::new(None);
    let duration = Target::new(300_000u32);
    let packets = Target::new(0u32);
    let verbosity = Target::new(0u32);
    let socket = Target::new(Filename {
        path: None,
        error: None,
    });
    let entries = Target::new(16384u32);
    let slice = Target::new(65535u32);
    let mut options = Options::new();
    match action {
        Action::Monitor => {
            options.add(helpers::flag(
                b'i',
                b"inbound-only",
                b"observe only original queries",
                inbound.clone(),
            ));
            options.add(helpers::flag(
                b'o',
                b"outbound-only",
                b"observe only final responses",
                outbound.clone(),
            ));
        }
        Action::Redirect => {
            options.add(helpers::string(
                b'4',
                b"ipv4",
                b"IPV4",
                b"replace answer-section A records",
                ipv4.clone(),
            ));
            options.add(helpers::string(
                b'6',
                b"ipv6",
                b"IPV6",
                b"replace answer-section AAAA records",
                ipv6.clone(),
            ));
        }
    }
    options.add(helpers::verbose(verbosity.clone()));
    options.add(helpers::uint(
        0,
        b"duration-ms",
        b"MS",
        b"finite run window (default300000ms)",
        duration.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"max-packets",
        b"COUNT",
        b"stop after callbacks;0 runs to original duration",
        packets.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"max-entries",
        b"COUNT",
        b"bounded counted DNS entries per packet",
        entries.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"io-slice-bytes",
        b"BYTES",
        b"actual MQ syscall byte slice",
        slice.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"socket",
        b"PATH",
        b"explicit Unix DNS service endpoint",
        socket.clone(),
    ));
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let clock = SharedClock::native(16)?;
    let binary = match action {
        Action::Monitor => b"gnunet-dns-monitor".as_slice(),
        Action::Redirect => b"gnunet-dns-redirector".as_slice(),
    };
    let mut logger = Logger::new(binary, std::process::id(), false)?;
    let prepared=program::prepare_installed(config,Invocation{binary_name:binary,help:Some(b"Actual official DNS interception monitor/answer redirector. -i/-o choose monitor directions; -4/-6 replace only answer A/AAAA. Whole write is local only; no subscription ACK. Default finite5-minute window, Native stop and parent control close the original MQ; reconnect resubscribes flags without replay."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let reporter = Reporter::new(logger, clock.clone());
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return if s.code == 0 {
                Ok(())
            } else {
                Err(format!("DNS utility PROGRAM stopped {:?} code={}", s.reason, s.code).into())
            };
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("DNS utility accepts no positional arguments".into());
    }
    let ms = duration.get()?;
    let count = entries.get()?;
    let slice = slice.get()?;
    if ms == 0 || ms > 86_400_000 || count == 0 || count > 16384 || slice == 0 || slice > 65535 {
        return Err("invalid finite DNS utility resource/time policy".into());
    }
    let duration = Duration::from_millis(u64::from(ms));
    if Instant::now().checked_add(duration).is_none() {
        return Err("DNS utility duration overflow".into());
    }
    let socket = socket.get()?;
    if let Some(e) = socket.error {
        return Err(format!("DNS socket expansion: {e}").into());
    }
    let ipv4 = ipv4
        .get()?
        .map(String::from_utf8)
        .transpose()?
        .map(|s| s.parse())
        .transpose()?;
    let ipv6 = ipv6
        .get()?
        .map(String::from_utf8)
        .transpose()?
        .map(|s| s.parse())
        .transpose()?;
    let flags = if action == Action::Redirect {
        ipc::POST_RESOLUTION
    } else {
        match (inbound.get()? != 0, outbound.get()? != 0) {
            (true, false) => ipc::REQUEST_MONITOR,
            (false, true) => ipc::RESPONSE_MONITOR,
            _ => ipc::REQUEST_MONITOR | ipc::RESPONSE_MONITOR,
        }
    };
    let settings = Settings {
        action,
        flags,
        ipv4,
        ipv6,
        duration,
        packets: packets.get()?,
        verbosity: verbosity.get()?,
        limits: dns::Limits {
            requests: 64,
            source_bytes: 4 * 1024 * 1024,
            io_slice_bytes: slice as usize,
            ..Default::default()
        },
        bounds: packet::Bounds {
            entries: count as usize,
            ..Default::default()
        },
        socket: socket.path,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(crate::execution::scheduled(
            prepared, clock, settings, reporter, parent,
        ))
}
