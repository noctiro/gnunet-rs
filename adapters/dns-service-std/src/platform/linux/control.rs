//! Linux fixed-purpose interception controls with observed routing effects.
use super::*;
use gnunet_native::linux_routing::{
    self, Acknowledgment, DefaultPresence, DirectDefault, Family, RouteChange, RouteInventory,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    num::NonZeroU32,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{Instant, timeout_at},
};
mod rules;
struct Output {
    status: ExitStatus,
    bytes: Vec<u8>,
}
async fn command(program: &Path, args: &[String], capture: bool) -> io::Result<Output> {
    let until = Instant::now() + Duration::from_secs(3);
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take();
    let result = timeout_at(until, async {
        let mut bytes = Vec::new();
        if let Some(pipe) = stdout.as_mut() {
            bytes
                .try_reserve_exact(65537)
                .map_err(|_| io::Error::other("DNS control query allocation"))?;
            pipe.take(65537).read_to_end(&mut bytes).await?;
            if bytes.len() > 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS control query bound",
                ));
            }
        }
        let status = child.wait().await?;
        Ok(Output { status, bytes })
    })
    .await;
    match result {
        Ok(Ok(out)) => Ok(out),
        other => {
            let original = match other {
                Ok(Err(e)) => e,
                Err(_) => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original DNS control process deadline",
                ),
                Ok(Ok(_)) => return Err(io::Error::other("unreachable DNS command outcome")),
            };
            let killed = child.kill().await;
            let waited = child.wait().await;
            if let Err(cleanup) = killed
                && cleanup.kind() != io::ErrorKind::InvalidInput
            {
                return Err(io::Error::other(format!(
                    "{original}; independent control kill: {cleanup}; wait={waited:?}"
                )));
            }
            Err(original)
        }
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
fn binary(candidates: &[&str]) -> io::Result<PathBuf> {
    for path in candidates {
        match std::fs::metadata(path) {
            Ok(m)
                if m.is_file()
                    && m.uid() == 0
                    && m.mode() & 0o022 == 0
                    && m.mode() & 0o111 != 0 =>
            {
                return Ok((*path).into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "approved root-owned DNS control utility unavailable",
    ))
}
#[derive(Debug)]
pub(super) struct Cleanup {
    errors: [Option<io::Error>; 10],
    count: usize,
}
impl Default for Cleanup {
    fn default() -> Self {
        Self {
            errors: std::array::from_fn(|_| None),
            count: 0,
        }
    }
}
impl Cleanup {
    fn push(&mut self, error: io::Error) {
        if let Some(slot) = self.errors.get_mut(self.count) {
            *slot = Some(error);
            self.count += 1;
        }
    }
    pub fn len(&self) -> usize {
        self.count
    }
}
struct Step {
    operation: Operation,
    admitted: bool,
}

enum Operation {
    Command(CommandStep),
    Route(DirectDefault),
}

struct CommandStep {
    program: PathBuf,
    add: Vec<String>,
    remove: Vec<String>,
    observation: Observation,
}

enum Observation {
    Firewall(Vec<String>),
    Rule(Vec<String>),
}

async fn route_inventory(route: DirectDefault) -> io::Result<RouteInventory> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    // The original worker performs one bounded, private read-only netlink dump.
    tokio::task::spawn_blocking(move || linux_routing::inventory(route, deadline))
        .await
        .map_err(io::Error::other)?
}

async fn change_route(route: DirectDefault, action: RouteChange) -> io::Result<Acknowledgment> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    tokio::task::spawn_blocking(move || linux_routing::change(route, action, deadline))
        .await
        .map_err(io::Error::other)?
}

impl CommandStep {
    async fn present(&self) -> io::Result<bool> {
        match &self.observation {
            Observation::Firewall(check) => {
                let present = command(&self.program, check, false).await?;
                if present.status.code() == Some(1) {
                    Ok(false)
                } else if present.status.success() {
                    Ok(true)
                } else {
                    Err(io::Error::other("DNS original rule presence unknown"))
                }
            }
            Observation::Rule(check) => {
                let present = command(&self.program, check, true).await?;
                if !present.status.success() {
                    return Err(io::Error::other("DNS original policy presence unknown"));
                }
                Ok(!present.bytes.iter().all(u8::is_ascii_whitespace))
            }
        }
    }
}

impl Step {
    async fn install(&mut self) -> io::Result<()> {
        self.admitted = true;
        match &self.operation {
            Operation::Command(step) => {
                let out = command(&step.program, &step.add, false).await?;
                if !out.status.success() {
                    return Err(io::Error::other(format!(
                        "DNS original control add failed: {}",
                        out.status
                    )));
                }
            }
            Operation::Route(route) => {
                if let Acknowledgment::Rejected(error) =
                    change_route(*route, RouteChange::Install).await?
                {
                    self.admitted = false;
                    return Err(error);
                }
                if !route_inventory(*route).await?.is_exclusive_default() {
                    return Err(io::Error::other(
                        "DNS default route lacks an exclusive table",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn retire(&mut self) -> io::Result<()> {
        if !self.admitted {
            return Ok(());
        }
        match &self.operation {
            Operation::Command(step) => {
                if step.present().await? {
                    let removed = command(&step.program, &step.remove, false).await?;
                    if !removed.status.success() {
                        return Err(io::Error::other(format!(
                            "DNS original control removal failed: {}",
                            removed.status
                        )));
                    }
                }
            }
            Operation::Route(route) => retire_route(*route).await?,
        }
        self.admitted = false;
        Ok(())
    }
}

async fn retire_route(route: DirectDefault) -> io::Result<()> {
    match route_inventory(route).await?.default_route() {
        DefaultPresence::Absent => return Ok(()),
        DefaultPresence::Exact => {}
        DefaultPresence::Conflicting => {
            return Err(io::Error::other(
                "DNS original default route changed or has conflicting selectors",
            ));
        }
    }
    if let Acknowledgment::Rejected(error) = change_route(route, RouteChange::Remove).await?
        && error.raw_os_error() != Some(libc::ESRCH)
    {
        return Err(error);
    }
    if route_inventory(route).await?.default_route() != DefaultPresence::Absent {
        return Err(io::Error::other(
            "DNS original default route removal not observed",
        ));
    }
    Ok(())
}
struct Sysctl {
    path: PathBuf,
    original: Vec<u8>,
    changed: bool,
}
/// One locked routing lease, with independent exact cleanup.
pub(super) struct Controls {
    _lock: File,
    steps: Vec<Step>,
    sysctl: Vec<Sysctl>,
}
impl Controls {
    pub async fn acquire(interface_index: u32, gid: u32, routing: Routing) -> io::Result<Self> {
        let path = Path::new("/run/gnunet-dns-rust.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let m = lock.metadata()?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS control lease policy",
            ));
        }
        lock.try_lock().map_err(io::Error::other)?;
        let ip = binary(&["/sbin/ip", "/usr/sbin/ip", "/bin/ip"])?;
        let ip4 = binary(&["/sbin/iptables", "/usr/sbin/iptables"])?;
        let ip6 = binary(&["/sbin/ip6tables", "/usr/sbin/ip6tables"])?;
        let table = routing.table.to_string();
        let priority = routing.priority.to_string();
        let mark = routing.mark.to_string();
        let index = NonZeroU32::new(interface_index)
            .ok_or_else(|| io::Error::other("missing original DNS interface index"))?;
        // This marker has no effect on route selection in the exclusive table.
        // It distinguishes our instance's row from ordinary defaults on the link.
        let metric = NonZeroU32::new(std::process::id())
            .ok_or_else(|| io::Error::other("missing original DNS process identity"))?;
        let routes = [("-4", Family::Ipv4), ("-6", Family::Ipv6)].map(|(flag, family)| {
            (
                flag,
                DirectDefault {
                    family,
                    table: routing.table,
                    interface: index,
                    metric,
                },
            )
        });
        // Never adopt a route or priority already used by the deployment.
        for (family, route) in routes {
            if !route_inventory(route).await?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("DNS routing table {table} is not empty"),
                ));
            }
            let query = args(&[family, "rule", "show", "priority", &priority]);
            let out = command(&ip, &query, true).await?;
            if !out.status.success() {
                return Err(io::Error::other(format!(
                    "DNS routing priority {priority} presence unknown"
                )));
            }
            if !out.bytes.iter().all(u8::is_ascii_whitespace) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("DNS routing priority {priority} is in use"),
                ));
            }
        }
        let tag = format!("GNUnet-DNS-Rust-{}", std::process::id());
        let gid = gid.to_string();
        let mut steps = Vec::new();
        steps
            .try_reserve_exact(8)
            .map_err(|_| io::Error::other("DNS control ledger allocation"))?;
        for (family, program) in [(rules::Family::Ipv4, ip4), (rules::Family::Ipv6, ip6)] {
            for action in [rules::Action::OwnerExemption, rules::Action::Intercept] {
                let rules::Commands { add, check, remove } =
                    rules::commands(family, action, &gid, &tag, &mark);
                let pre = command(&program, &check, false).await?;
                if pre.status.success() || pre.status.code() != Some(1) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "DNS exact rule is present or query unknown",
                    ));
                }
                steps.push(Step {
                    operation: Operation::Command(CommandStep {
                        program: program.clone(),
                        add,
                        remove,
                        observation: Observation::Firewall(check),
                    }),
                    admitted: false,
                });
            }
        }
        for family in ["-4", "-6"] {
            steps.push(Step {
                operation: Operation::Command(CommandStep {
                    program: ip.clone(),
                    add: args(&[
                        family, "rule", "add", "priority", &priority, "fwmark", &mark, "table",
                        &table, "protocol", "static",
                    ]),
                    remove: args(&[
                        family, "rule", "del", "priority", &priority, "fwmark", &mark, "table",
                        &table, "protocol", "static",
                    ]),
                    observation: Observation::Rule(args(&[
                        family, "rule", "show", "priority", &priority,
                    ])),
                }),
                admitted: false,
            });
        }
        for (_, route) in routes {
            steps.push(Step {
                operation: Operation::Route(route),
                admitted: false,
            });
        }
        let mut sysctl = Vec::new();
        sysctl
            .try_reserve_exact(2)
            .map_err(|_| io::Error::other("DNS sysctl ledger allocation"))?;
        for name in ["all", "default"] {
            let path = PathBuf::from(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"));
            let original = read_sysctl(&path)?;
            sysctl.push(Sysctl {
                path,
                original,
                changed: false,
            });
        }
        Ok(Self {
            _lock: lock,
            steps,
            sysctl,
        })
    }
    pub async fn install(&mut self) -> io::Result<()> {
        for row in &mut self.sysctl {
            if row.original != b"0\n" && row.original != b"0" {
                row.changed = true;
                write_sysctl(&row.path, b"0\n")?;
                if read_sysctl(&row.path)?.as_slice() != b"0\n" {
                    return Err(io::Error::other("DNS rp_filter write not observed"));
                }
            }
        }
        // Install routes/rules before enabling packet marking. This preserves the
        // official mark/table semantics while avoiding a transient black-hole window.
        for i in [6usize, 7, 4, 5, 0, 2, 1, 3] {
            self.steps[i].install().await?;
        }
        Ok(())
    }
    pub async fn cleanup(&mut self) -> Cleanup {
        let mut errors = Cleanup::default();
        // Remove mark first, exemption second, then policy rules/routes. Every
        // actually admitted/unknown command gets an original exact presence query.
        for i in [3usize, 1, 2, 0, 5, 4, 7, 6] {
            if let Err(e) = self.steps[i].retire().await {
                errors.push(e);
            }
        }
        for row in self.sysctl.iter_mut().rev() {
            if !row.changed {
                continue;
            }
            let result = (|| {
                let current = read_sysctl(&row.path)?;
                if current == row.original {
                    row.changed = false;
                    return Ok(());
                }
                if current != b"0\n" && current != b"0" {
                    return Err(io::Error::other(
                        "DNS rp_filter changed externally; restore refused",
                    ));
                }
                write_sysctl(&row.path, &row.original)?;
                if read_sysctl(&row.path)? != row.original {
                    return Err(io::Error::other("DNS rp_filter restoration not observed"));
                }
                row.changed = false;
                Ok(())
            })();
            if let Err(e) = result {
                errors.push(e);
            }
        }
        errors
    }
}
fn read_sysctl(path: &Path) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(5)
        .map_err(|_| io::Error::other("DNS sysctl read allocation"))?;
    File::open(path)?.take(5).read_to_end(&mut out)?;
    if out.len() > 4
        || !matches!(
            out.as_slice(),
            b"0" | b"0\n" | b"1" | b"1\n" | b"2" | b"2\n"
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS rp_filter state",
        ));
    }
    Ok(out)
}
fn write_sysctl(path: &Path, value: &[u8]) -> io::Result<()> {
    OpenOptions::new().write(true).open(path)?.write_all(value)
}
