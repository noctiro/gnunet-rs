//! Configured VPN allocation with the official PROGRAM flags and address output.
use super::{
    AfProfile, Client, EndpointSource, Family, Instance, Limits, Protocol, Result, Service, Target,
    address, observe, peer,
};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target as Value},
};
use std::{
    ffi::OsStr,
    io::{self, Write},
    net::IpAddr,
    time::Duration,
};
use tokio::time::Instant;

const DEFAULT_LEASE: u64 = 300_000;
const RESPONSE_MICROS: u64 = 10_000_000;
const DRAIN_MICROS: u64 = 6_000_000;

struct Arguments {
    ipv4: Value<i32>,
    ipv6: Value<i32>,
    duration: Value<u64>,
    ip: Value<Option<Vec<u8>>>,
    peer: Value<Option<Vec<u8>>>,
    service: Value<Option<Vec<u8>>>,
    tcp: Value<i32>,
    udp: Value<i32>,
}

struct Request {
    target: Target,
    desired: Option<Family>,
    duration: u64,
}

impl Arguments {
    fn new() -> Self {
        Self {
            ipv4: Value::new(0),
            ipv6: Value::new(0),
            duration: Value::new(DEFAULT_LEASE),
            ip: Value::new(None),
            peer: Value::new(None),
            service: Value::new(None),
            tcp: Value::new(0),
            udp: Value::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::flag(
            b'4',
            b"ipv4",
            b"request that result should be an IPv4 address",
            self.ipv4.clone(),
        ));
        options.add(helpers::flag(
            b'6',
            b"ipv6",
            b"request that result should be an IPv6 address",
            self.ipv6.clone(),
        ));
        options.add(helpers::relative_time(
            b'd',
            b"duration",
            b"TIME",
            b"how long should the mapping be valid for new tunnels?",
            self.duration.clone(),
        ));
        options.add(helpers::string(
            b'i',
            b"ip",
            b"IP",
            b"destination IP for the tunnel",
            self.ip.clone(),
        ));
        options.add(helpers::string(
            b'p',
            b"peer",
            b"PEERID",
            b"peer offering the service we would like to access",
            self.peer.clone(),
        ));
        options.add(helpers::string(
            b's',
            b"service",
            b"NAME",
            b"name of the service we would like to access",
            self.service.clone(),
        ));
        options.add(helpers::flag(
            b't',
            b"tcp",
            b"service is offered via TCP",
            self.tcp.clone(),
        ));
        options.add(helpers::flag(
            b'u',
            b"udp",
            b"service is offered via UDP",
            self.udp.clone(),
        ));
        options.add(helpers::verbose(Value::new(0)));
        options
    }

    fn request(&self) -> Result<Request> {
        let desired = match (self.ipv4.get()? != 0, self.ipv6.get()? != 0) {
            (true, true) => return Err("Option `-4' makes no sense with option `-6'.".into()),
            (true, false) => Some(Family::V4),
            (false, true) => Some(Family::V6),
            (false, false) => None,
        };
        let target = match self.ip.get()? {
            Some(value) => {
                let value = std::str::from_utf8(&value)?;
                let ip = value
                    .parse()
                    .map_err(|_| format!("`{value}' is not a valid IP address."))?;
                Target::Internet(address(ip))
            }
            None => self.service_target()?,
        };
        Ok(Request {
            target,
            desired,
            duration: self.duration.get()?,
        })
    }

    fn service_target(&self) -> Result<Target> {
        let name = self
            .service
            .get()?
            .ok_or("Option `-i' or `-s' is required.")?;
        let identity = self
            .peer
            .get()?
            .ok_or("Option `-p' is required when using option `-s'.")?;
        let protocol = match (self.tcp.get()? != 0, self.udp.get()? != 0) {
            (true, false) => Protocol::Tcp,
            (false, true) => Protocol::Udp,
            (true, true) => return Err("Option `-t' makes no sense with option `-u'.".into()),
            (false, false) => {
                return Err("Option `-t' or `-u' is required when using option `-s'.".into());
            }
        };
        let invalid = || {
            format!(
                "`{}' is not a valid peer identifier.",
                String::from_utf8_lossy(&identity)
            )
        };
        // The C EdDSA key reader accepts exactly 52 Crockford characters.
        if identity.len() != 52 {
            return Err(invalid().into());
        }
        let text = std::str::from_utf8(&identity).map_err(|_| invalid())?;
        Ok(Target::Service(Service {
            peer: peer(OsStr::new(text)).map_err(|_| invalid())?,
            descriptor: gnunet::vpn::service_descriptor(&name),
            protocol,
        }))
    }
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-vpn",
        b"Setup tunnels via VPN.",
        arguments.options(),
    )?
    else {
        return Ok(());
    };
    let request = arguments.request()?;
    let ip = crate::configured::run(prepared.main().config, clock, [b"vpn"], |[source]| {
        allocate(source, request)
    })?;
    let mut out = io::stdout().lock();
    writeln!(out, "{ip}")?;
    out.flush()?;
    Ok(())
}

async fn allocate(source: EndpointSource, request: Request) -> Result<IpAddr> {
    let wall = Instant::now() + Duration::from_micros(RESPONSE_MICROS + DRAIN_MICROS);
    let now = source.clock().sample()?.now.as_micros();
    let response_until = now
        .checked_add(RESPONSE_MICROS)
        .ok_or("VPN deadline overflow")?;
    let lease = now.saturating_add(request.duration);
    let mut instance = Instance::new();
    let mut client = Client::new(
        &mut instance,
        source,
        AfProfile::native(),
        Limits {
            operations: 1,
            ..Limits::default()
        },
    )?;
    let operation = request
        .target
        .submit(&mut client, request.desired, lease, response_until)?;
    let result = observe(&mut client, operation, wall, None).await;
    let cleanup = client.close();
    let ip = result?;
    cleanup?;
    Ok(ip)
}
