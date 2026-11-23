//! Explicit foreground configuration, with no implicit service directories.
use crate::Result;
use gnunet_config::Configuration;
use gnunet_node_host::{
    MachineInputs, NatHelperPrograms, Node, Paths, PeerTransport, ResolverInputs, Settings,
    SystemDns, TcpBind, Timing, UdpBind, Upstreams,
};
use std::{ffi::OsString, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

pub(super) struct Options {
    paths: Paths,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    storage_mount: Option<PathBuf>,
    config: Option<PathBuf>,
    bootstrap_data_dir: Option<PathBuf>,
    peers: PeerTransport,
    resolver: ResolverInputs,
    nat_helpers: Option<NatHelperPrograms>,
    timing: Timing,
}

impl Options {
    #[cfg(windows)]
    pub(super) fn timing(&self) -> &Timing {
        &self.timing
    }

    pub(super) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut state = None;
        let mut ipc = None;
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        let mut storage_mount = None;
        let mut config = None;
        let mut bootstrap_data_dir = None;
        let mut outbound = false;
        let mut tcp = None;
        let mut udp4 = None;
        let mut udp6 = None;
        let mut startup_ms = None;
        let mut drain_ms = None;
        let mut dns = Vec::new();
        let mut system_dns = false;
        let mut nat_helpers_directory = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let flag = arg.to_str().ok_or("invalid option name")?;
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("missing value for {flag}"))
            };
            match flag {
                "--state-directory" => set(&mut state, absolute(value()?, flag)?, flag)?,
                "--ipc-directory" => set(&mut ipc, absolute(value()?, flag)?, flag)?,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                "--require-storage-mount" => {
                    set(&mut storage_mount, absolute(value()?, flag)?, flag)?;
                }
                "--config" => set(&mut config, PathBuf::from(value()?), flag)?,
                "--bootstrap-data-directory" => {
                    set(&mut bootstrap_data_dir, absolute(value()?, flag)?, flag)?;
                }
                "--outbound-tcp" if !outbound => outbound = true,
                "--outbound-tcp" => return Err("duplicate --outbound-tcp".into()),
                "--tcp-bind" => set(
                    &mut tcp,
                    TcpBind::Address(parse(value()?, flag)?),
                    "TCP bind",
                )?,
                "--tcp-dual-stack" => set(
                    &mut tcp,
                    TcpBind::DualStack(parse(value()?, flag)?),
                    "TCP bind",
                )?,
                "--udp4-bind" => set(&mut udp4, parse(value()?, flag)?, flag)?,
                "--udp6-bind" => set(&mut udp6, parse(value()?, flag)?, flag)?,
                "--startup-timeout-ms" => {
                    set(&mut startup_ms, parse::<u32>(value()?, flag)?, flag)?
                }
                "--drain-timeout-ms" => set(&mut drain_ms, parse::<u32>(value()?, flag)?, flag)?,
                "--dns-server" => {
                    let endpoint: SocketAddr = parse(value()?, flag)?;
                    if !dns.contains(&endpoint) {
                        if dns.len() >= Upstreams::MAX_ENDPOINTS {
                            return Err("too many distinct DNS servers".into());
                        }
                        dns.push(endpoint);
                    }
                }
                "--system-dns" if !system_dns => system_dns = true,
                "--system-dns" => return Err("duplicate --system-dns".into()),
                "--nat-helpers-directory" => {
                    set(&mut nat_helpers_directory, absolute(value()?, flag)?, flag)?;
                }
                _ => return Err(format!("unknown option {flag}. See --help").into()),
            }
        }
        let state = state.ok_or("--state-directory is required")?;
        let ipc = ipc.ok_or("--ipc-directory is required")?;
        if state == ipc {
            return Err("state and IPC directories must be distinct".into());
        }
        let peers = if outbound {
            if tcp.is_some() || udp4.is_some() || udp6.is_some() {
                return Err("--outbound-tcp excludes all peer bind options".into());
            }
            PeerTransport::OutboundTcp
        } else {
            PeerTransport::Listening {
                tcp: tcp.ok_or("--tcp-bind or --tcp-dual-stack is required for listening")?,
                udp: UdpBind {
                    ipv4: udp4.ok_or("--udp4-bind is required for listening")?,
                    ipv6: udp6,
                },
            }
        };
        let resolver = if system_dns {
            if !dns.is_empty() {
                return Err("--system-dns excludes --dns-server".into());
            }
            ResolverInputs::System(system_resolver()?)
        } else {
            ResolverInputs::Datagram(MachineInputs {
                dns_endpoints: Upstreams::new(dns)?.into_endpoints(),
                ..MachineInputs::default()
            })
        };
        let nat_helpers = nat_helpers_directory
            .map(|directory| {
                let suffix = std::env::consts::EXE_SUFFIX;
                NatHelperPrograms::new(
                    directory.join(format!("gnunet-helper-nat-server{suffix}")),
                    directory.join(format!("gnunet-helper-nat-client{suffix}")),
                )
            })
            .transpose()?;
        Ok(Self {
            paths: Paths { state, ipc },
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            storage_mount,
            config,
            bootstrap_data_dir,
            peers,
            resolver,
            nat_helpers,
            timing: Timing::new(
                Duration::from_millis(u64::from(startup_ms.unwrap_or(30_000))),
                Duration::from_millis(u64::from(drain_ms.unwrap_or(10_000))),
            )?,
        })
    }

    pub(super) fn prepare(self) -> Result<Node> {
        let mut config = Configuration::default();
        if let Some(path) = &self.config {
            config.load_explicit(None, Some(path))?;
        }
        let settings = Settings {
            config,
            bootstrap_data_dir: self.bootstrap_data_dir,
            paths: self.paths,
            peers: self.peers,
            vpn: None,
            socket_policy: Default::default(),
            resolver: self.resolver,
            nat_helpers: self.nat_helpers,
            timing: self.timing,
        };
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if let Some(mount) = &self.storage_mount {
            return Node::new_on_mount(settings, mount);
        }
        Node::new(settings)
    }
}

fn system_resolver() -> std::io::Result<SystemDns> {
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    ))]
    {
        SystemDns::for_worker(std::env::current_exe()?)
    }
    #[cfg(not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    )))]
    {
        SystemDns::new()
    }
}

fn absolute(value: OsString, flag: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{flag} requires an absolute path").into());
    }
    Ok(path)
}

fn parse<T: FromStr>(value: OsString, flag: &str) -> Result<T> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("invalid value for {flag}").into())
}

fn set<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<()> {
    if slot.is_some() {
        return Err(format!("duplicate or conflicting {flag}").into());
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> impl Iterator<Item = OsString> {
        let base = std::env::temp_dir();
        [
            "--state-directory".into(),
            base.join("node-test-state").into_os_string(),
            "--ipc-directory".into(),
            base.join("node-test-ipc").into_os_string(),
        ]
        .into_iter()
        .chain(extra.iter().copied().map(OsString::from))
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert selected original bind and DNS policy"
    )]
    fn selects_explicit_roles_and_ordered_resolvers() -> Result<()> {
        let listening = Options::parse(args(&[
            "--tcp-dual-stack",
            "4321",
            "--udp4-bind",
            "127.0.0.1:0",
            "--udp6-bind",
            "[::1]:0",
            "--dns-server",
            "192.0.2.53:5353",
            "--dns-server",
            "[fe80::1%4]:53",
            "--dns-server",
            "192.0.2.53:5353",
        ]))?;
        assert!(matches!(listening.peers, PeerTransport::Listening {
            tcp: TcpBind::DualStack(port), udp: UdpBind { ipv6: Some(_), .. }
        } if port.get() == 4321));
        let ResolverInputs::Datagram(inputs) = listening.resolver else {
            return Err("expected configured DNS datagrams".into());
        };
        assert_eq!(
            &inputs.dns_endpoints,
            &[
                "192.0.2.53:5353".parse::<SocketAddr>()?,
                "[fe80::1%4]:53".parse::<SocketAddr>()?
            ]
        );
        let outbound = Options::parse(args(&["--outbound-tcp"]))?;
        assert!(matches!(outbound.peers, PeerTransport::OutboundTcp));
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_roles_before_startup() {
        for invalid in [
            &["--outbound-tcp", "--tcp-bind", "127.0.0.1:0"][..],
            &["--tcp-bind", "127.0.0.1:0", "--tcp-dual-stack", "4000"][..],
            &["--udp4-bind", "127.0.0.1:0"][..],
            &["--tcp-bind", "127.0.0.1:0"][..],
            &["--outbound-tcp", "--bootstrap-data-directory", "relative"][..],
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            &["--outbound-tcp", "--require-storage-mount", "relative"][..],
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            &[
                "--outbound-tcp",
                "--require-storage-mount",
                "/first",
                "--require-storage-mount",
                "/second",
            ][..],
            &["--outbound-tcp", "--nat-helpers-directory", "relative"][..],
            &["--outbound-tcp", "--dns-server", "127.0.0.1:0"][..],
            &[
                "--outbound-tcp",
                "--system-dns",
                "--dns-server",
                "127.0.0.1:53",
            ][..],
            &["--outbound-tcp", "--system-dns", "--system-dns"][..],
            &["--outbound-tcp", "--startup-timeout-ms", "0"][..],
        ] {
            assert!(Options::parse(args(invalid)).is_err());
        }
    }
}
