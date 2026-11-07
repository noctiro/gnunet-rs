//! Finite official VPN address allocation over one explicit Unix IPC endpoint.
use super::peer::parse as peer;
use gnunet::clients::vpn::{
    Address, AfProfile, Client, EndpointSource, Family, Instance, Limits, Operation, Outcome,
    Progress, Protocol, Reason, Service, Submission,
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    future::{Future, poll_fn},
    io::{self, Write},
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

enum Target {
    Internet(Address),
    Service(Service),
}
struct Command {
    socket: PathBuf,
    target: Target,
    desired: Option<Family>,
    profile: AfProfile,
    lease_millis: Option<u64>,
    timeout_millis: u64,
}
fn text(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| "expected a UTF-8 VPN argument".into())
}
fn address(value: IpAddr) -> Address {
    match value {
        IpAddr::V4(value) => Address::V4(value.octets()),
        IpAddr::V6(value) => Address::V6(value.octets()),
    }
}
fn parse(args: &[OsString]) -> Result<Command> {
    let (target, required) = match args.first().map(OsString::as_os_str) {
        Some(action) if action == "internet" && args.len() >= 3 => {
            (Target::Internet(address(text(&args[2])?.parse()?)), 3)
        }
        Some(action) if action == "service" && args.len() >= 5 => {
            let protocol = match text(&args[4])? {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err("service protocol must be tcp or udp".into()),
            };
            (
                Target::Service(Service {
                    peer: peer(&args[2])?,
                    descriptor: gnunet::vpn::service_descriptor(text(&args[3])?.as_bytes()),
                    protocol,
                }),
                5,
            )
        }
        _ => return Err("expected vpn internet|service arguments; see vpn --help".into()),
    };
    let mut command = Command {
        socket: PathBuf::from(&args[1]),
        target,
        desired: None,
        profile: AfProfile::native(),
        lease_millis: Some(300_000),
        timeout_millis: 10_000,
    };
    let mut at = required;
    while at < args.len() {
        let flag = text(&args[at])?;
        let value = text(args.get(at + 1).ok_or("missing VPN option value")?)?;
        at += 2;
        match flag {
            "--family" => {
                command.desired = match value {
                    "4" => Some(Family::V4),
                    "6" => Some(Family::V6),
                    "any" => None,
                    _ => return Err("result family must be 4, 6 or any".into()),
                }
            }
            "--af-profile" => {
                command.profile = match value {
                    "native" => AfProfile::native(),
                    "linux" => AfProfile::LINUX,
                    "darwin" => AfProfile::DARWIN,
                    _ => return Err("AF profile must be native, linux or darwin".into()),
                }
            }
            "--lease-ms" => {
                command.lease_millis = if value == "forever" {
                    None
                } else {
                    Some(value.parse()?)
                }
            }
            "--timeout-ms" => command.timeout_millis = value.parse()?,
            _ => return Err(format!("unknown VPN option: {flag}").into()),
        }
    }
    if command.timeout_millis == 0 || command.lease_millis == Some(0) {
        return Err("VPN timeout and finite lease must be nonzero".into());
    }
    Ok(command)
}
fn row(out: &mut impl Write, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
async fn wait<'id>(
    client: &mut Client<'id>,
    deadline: Instant,
    mut interrupt: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<Option<Progress<'id>>> {
    let driving = client.drive(Some(deadline));
    let mut driving = std::pin::pin!(driving);
    poll_fn(|cx| {
        if let Poll::Ready(result) = interrupt.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None).map_err(Into::into));
        }
        driving
            .as_mut()
            .poll(cx)
            .map(|result| result.map(Some).map_err(Into::into))
    })
    .await
}
async fn observe<'id>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    deadline: Instant,
    lease_until: u64,
    out: &mut impl Write,
) -> Result<()> {
    let interrupt = tokio::signal::ctrl_c();
    let mut interrupt = std::pin::pin!(interrupt);
    let mut cancelling = false;
    loop {
        let progress = if cancelling {
            client.drive(Some(deadline)).await?
        } else if let Some(progress) = wait(client, deadline, interrupt.as_mut()).await? {
            progress
        } else {
            cancelling = true;
            let local = client.cancel(operation)?;
            row(
                out,
                serde_json::json!({"event":"vpn_cancel","local":format!("{local:?}")}),
            )?;
            continue;
        };
        match progress {
            Progress::Completed {
                operation: original,
                outcome,
                ..
            } if original == operation => {
                return match outcome {
                    Outcome::Allocation(allocated) => {
                        let ip = allocated.map(|a| match a {
                            Address::V4(a) => IpAddr::from(a),
                            Address::V6(a) => IpAddr::from(a),
                        });
                        row(
                            out,
                            serde_json::json!({"event":"vpn_allocation","allocated":ip.is_some(),
                            "address":ip.map(|a|a.to_string()),"lease_until":lease_until}),
                        )?;
                        if ip.is_some() {
                            Ok(())
                        } else {
                            Err("VPN service could not allocate an address".into())
                        }
                    }
                    Outcome::Local { reason, submission } => {
                        let reason = match reason {
                            Reason::Cancelled => "cancelled",
                            Reason::Deadline => "deadline",
                            Reason::Lost => "lost",
                            Reason::Closed => "closed",
                        };
                        let exposure = match submission {
                            Submission::Unsent => "unsent",
                            Submission::Unknown => "unknown",
                        };
                        row(
                            out,
                            serde_json::json!({"event":"vpn_local_end","reason":reason,"submission":exposure}),
                        )?;
                        Err(format!(
                            "VPN {reason}; allocation result was not observed ({exposure})"
                        )
                        .into())
                    }
                };
            }
            Progress::WaitDeadline => {
                return Err("VPN observation/drain deadline before allocation settlement".into());
            }
            Progress::Unavailable(error) => return Err(error.into()),
            Progress::Closed => return Err("VPN client closed without an allocation result".into()),
            Progress::ConnectRetry { error, retry_after } => row(
                out,
                serde_json::json!({
                "event":"vpn_connect_retry","error":error.to_string(),"retry_after_micros":retry_after.as_micros()}),
            )?,
            _ => {}
        }
    }
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|arg| arg == "--help") {
        writeln!(out, "vpn internet <UNIXPATH> <IP> [options]")?;
        writeln!(
            out,
            "vpn service <UNIXPATH> <PEER> <SERVICE_NAME> <tcp|udp> [options]"
        )?;
        writeln!(
            out,
            "Options: --family 4|6|any --lease-ms N|forever --timeout-ms N --af-profile native|linux|darwin"
        )?;
        writeln!(
            out,
            "Defaults: any family, 300000 ms lease, 10000 ms response timeout, native endpoint AF profile. PEER accepts official GNUnet text or hex. Only an actual allocation result succeeds; it does not establish packet forwarding or a host route. Cancellation suppresses the local result and can leave a lease."
        )?;
        return Ok(());
    }
    let command = parse(args)?; // Validate all arguments before native IO.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let duration = Duration::from_millis(command.timeout_millis);
            let wall = Instant::now()
                .checked_add(duration)
                .ok_or("VPN timeout overflow")?;
            let deadline = wall
                .checked_add(Duration::from_secs(6))
                .ok_or("VPN drain deadline overflow")?;
            let source = EndpointSource::unix(command.socket);
            let now = source.clock().sample()?.now.as_micros();
            let until = now
                .checked_add(u64::try_from(duration.as_micros())?)
                .filter(|until| *until < u64::MAX - 5_000_000)
                .ok_or("VPN response deadline overflow")?;
            let lease = command
                .lease_millis
                .map(|n| {
                    n.checked_mul(1000)
                        .and_then(|n| now.checked_add(n))
                        .filter(|expiry| *expiry < u64::MAX)
                        .ok_or("VPN lease deadline overflow")
                })
                .transpose()?
                .unwrap_or(u64::MAX);
            let mut instance = Instance::new();
            let mut client = Client::new(
                &mut instance,
                source,
                command.profile,
                Limits {
                    operations: 1,
                    ..Limits::default()
                },
            )?;
            let operation = match command.target {
                Target::Internet(destination) => {
                    client.internet(destination, command.desired, lease, until)?
                }
                Target::Service(target) => client.service(target, command.desired, lease, until)?,
            };
            let result = observe(&mut client, operation, deadline, lease, out).await;
            let cleanup = client.close();
            match (result, cleanup) {
                (Err(error), _) => Err(error),
                (Ok(()), Err(error)) => Err(error.into()),
                (Ok(()), Ok(_)) => Ok(()),
            }
        })
}
