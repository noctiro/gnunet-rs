//! Linux fixed-purpose interception controls. Only real original child exits
//! and read-only presence observations settle owned firewall/routing effects.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{Instant, timeout_at},
};
const MARK: &str = "136708149";
const TABLE: &str = "53";
const PRIORITY: &str = "1053";
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
    program: PathBuf,
    add: Vec<String>,
    remove: Vec<String>,
    check: Vec<String>,
    iptables: bool,
    admitted: bool,
}
struct Sysctl {
    path: PathBuf,
    original: Vec<u8>,
    changed: bool,
}
/// One locked original fixed mark/table lease, with independent exact cleanup.
pub(super) struct Controls {
    _lock: File,
    steps: Vec<Step>,
    sysctl: Vec<Sysctl>,
}
impl Controls {
    pub async fn acquire(interface: &str, gid: u32) -> io::Result<Self> {
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
        // Do not silently share or remove another administrator's existing table or
        // priority. This helper owns only a fresh exclusive TUN and absent namespace.
        for family in ["-4", "-6"] {
            for query in [
                args(&[family, "route", "show", "table", TABLE]),
                args(&[family, "rule", "show", "priority", PRIORITY]),
            ] {
                let out = command(&ip, &query, true).await?;
                if !out.status.success() || !out.bytes.iter().all(u8::is_ascii_whitespace) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "DNS table53/priority1053 is not empty",
                    ));
                }
            }
        }
        let tag = format!("GNUnet-DNS-Rust-{}", std::process::id());
        let gid = gid.to_string();
        let mut steps = Vec::new();
        steps
            .try_reserve_exact(8)
            .map_err(|_| io::Error::other("DNS control ledger allocation"))?;
        for (family, program) in [(false, ip4), (true, ip6)] {
            for owner in [true, false] {
                let mut rule = args(&[
                    "-t",
                    "mangle",
                    "-I",
                    "OUTPUT",
                    if owner { "1" } else { "2" },
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                ]);
                if owner {
                    rule.extend(args(&["-m", "owner", "--gid-owner", &gid]));
                } else if family {
                    rule.extend(args(&["!", "-s", "fe80::/10"]));
                }
                rule.extend(args(&[
                    "-m",
                    "comment",
                    "--comment",
                    &tag,
                    "-j",
                    if owner { "ACCEPT" } else { "MARK" },
                ]));
                if !owner {
                    rule.extend(args(&["--set-mark", MARK]));
                }
                let mut check = rule.clone();
                check.remove(4);
                check[2] = "-C".into();
                let mut remove = rule.clone();
                remove.remove(4);
                remove[2] = "-D".into();
                let pre = command(&program, &check, false).await?;
                if pre.status.success() || pre.status.code() != Some(1) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "DNS exact rule is present or query unknown",
                    ));
                }
                steps.push(Step {
                    program: program.clone(),
                    add: rule,
                    remove,
                    check,
                    iptables: true,
                    admitted: false,
                });
            }
        }
        for family in ["-4", "-6"] {
            steps.push(Step {
                program: ip.clone(),
                add: args(&[
                    family, "rule", "add", "priority", PRIORITY, "fwmark", MARK, "table", TABLE,
                    "protocol", "static",
                ]),
                remove: args(&[
                    family, "rule", "del", "priority", PRIORITY, "fwmark", MARK, "table", TABLE,
                    "protocol", "static",
                ]),
                check: args(&[family, "rule", "show", "priority", PRIORITY]),
                iptables: false,
                admitted: false,
            });
        }
        for family in ["-4", "-6"] {
            steps.push(Step {
                program: ip.clone(),
                add: args(&[
                    family, "route", "add", "default", "dev", interface, "table", TABLE, "proto",
                    "static",
                ]),
                remove: args(&[
                    family, "route", "del", "default", "dev", interface, "table", TABLE, "proto",
                    "static",
                ]),
                check: args(&[
                    family, "route", "show", "table", TABLE, "default", "dev", interface,
                ]),
                iptables: false,
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
            let row = &mut self.steps[i];
            row.admitted = true;
            let out = command(&row.program, &row.add, false).await?;
            if !out.status.success() {
                return Err(io::Error::other(format!(
                    "DNS original control add failed: {}",
                    out.status
                )));
            }
        }
        Ok(())
    }
    pub async fn cleanup(&mut self) -> Cleanup {
        let mut errors = Cleanup::default();
        // Remove mark first, exemption second, then policy rules/routes. Every
        // actually admitted/unknown command gets an original exact presence query.
        for i in [3usize, 1, 2, 0, 5, 4, 7, 6] {
            let row = &mut self.steps[i];
            if !row.admitted {
                continue;
            }
            let result = async {
                let present = command(&row.program, &row.check, true).await?;
                let exists = if row.iptables {
                    if present.status.code() == Some(1) {
                        false
                    } else if present.status.success() {
                        true
                    } else {
                        return Err(io::Error::other("DNS original rule presence unknown"));
                    }
                } else {
                    if !present.status.success() {
                        return Err(io::Error::other("DNS original policy presence unknown"));
                    }
                    !present.bytes.iter().all(u8::is_ascii_whitespace)
                };
                if exists {
                    let removed = command(&row.program, &row.remove, false).await?;
                    if !removed.status.success() {
                        return Err(io::Error::other(format!(
                            "DNS original control removal failed: {}",
                            removed.status
                        )));
                    }
                }
                row.admitted = false;
                Ok::<_, io::Error>(())
            }
            .await;
            if let Err(e) = result {
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
