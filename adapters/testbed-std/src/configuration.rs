//! Active configuration_create semantics using the shared official CONFIG.
use crate::*;
use gnunet_config::Configuration;
use std::{fs::DirBuilder, net::IpAddr, os::unix::fs::DirBuilderExt};
/// An actual generated configuration plus its exact logical port/path ownership.
/// It contains no fake peer/controller object or ready state.
pub struct Generated<'id> {
    pub(crate) id: core::PathId<'id>,
    pub(crate) home: PathBuf,
    pub(crate) configuration: Configuration,
    pub(crate) ports: Vec<core::Reservation<'id>>,
}
impl<'id> Generated<'id> {
    /// Borrow the actual complete official configuration.
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    /// Explicitly customize the actual generated CONFIG before publication;
    /// changing a port does not transfer any logical reservation or start a peer.
    pub fn configuration_mut(&mut self) -> &mut Configuration {
        &mut self.configuration
    }
    /// Actual original unique GNUNET_HOME path, not process liveness proof.
    pub fn home(&self) -> &Path {
        &self.home
    }
    /// Actual PATHS.DEFAULTCONFIG / ARM.CONFIG publication target.
    pub fn default_config(&self) -> PathBuf {
        self.home.join("config")
    }
    /// Exact original path resource.
    pub const fn id(&self) -> core::PathId<'id> {
        self.id
    }
    /// Exact logical reservations, not future exclusive native port leases.
    pub fn ports(&self) -> impl Iterator<Item = core::Reservation<'id>> + '_ {
        self.ports.iter().copied()
    }
}
impl std::fmt::Debug for Generated<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedTestbedConfiguration([VALUES REDACTED])")
            .field("path", &self.id)
            .field("ports", &self.ports.len())
            .finish_non_exhaustive()
    }
}
pub(crate) fn validate_options(options: &Options) -> Result<(), Failure> {
    if let Some(host) = &options.hostname
        && (host.is_empty() || host.len() > options.limits.configuration_bytes || host.contains(&0))
    {
        return Err(Fault::InvalidInput.into());
    }
    if let Some(trusted) = &options.trusted_ip {
        let (ip, prefix) = trusted
            .split_once('/')
            .map_or((trusted.as_str(), None), |(a, b)| (a, Some(b)));
        let ip: IpAddr = ip.parse().map_err(|_| Fault::InvalidInput)?;
        if let Some(p) = prefix {
            let p: u8 = p.parse().map_err(|_| Fault::InvalidInput)?;
            if p > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(Fault::InvalidInput.into());
            }
        }
    }
    Ok(())
}
fn copied(bytes: &[u8], limit: usize) -> Result<Vec<u8>, Failure> {
    if bytes.len() > limit {
        return Err(Fault::TooLarge.into());
    }
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn single_key(section: &[u8], limit: usize) -> Result<Vec<u8>, Failure> {
    let n = section.len().checked_add(16).ok_or(Fault::Overflow)?;
    if n > limit {
        return Err(Fault::TooLarge.into());
    }
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(b"single_");
    out.extend_from_slice(section);
    out.extend_from_slice(b"_per_host");
    Ok(out)
}
fn ignored(config: &Configuration, section: &[u8], key: &[u8]) -> bool {
    config
        .get(section, b"TESTBED_IGNORE_KEYS")
        .is_some_and(|bytes| {
            bytes
                .split(|b| *b == b';')
                .any(|token| token.eq_ignore_ascii_case(key))
        })
}
fn append_acl(
    config: &mut Configuration,
    section: &[u8],
    trusted: Option<&str>,
    limit: usize,
) -> Result<(), Failure> {
    let v6 = trusted.is_some_and(|ip| ip.contains(':'));
    let key = if v6 {
        b"ACCEPT_FROM6".as_slice()
    } else {
        b"ACCEPT_FROM".as_slice()
    };
    if ignored(config, section, key) || ignored(config, section, b"ACCEPT_FROM") {
        return Ok(());
    }
    let default = if v6 {
        b"::1;".as_slice()
    } else {
        b"127.0.0.1;".as_slice()
    };
    let old = config.get(section, key).unwrap_or(default);
    let additional = trusted.map_or(0, |t| t.len() + 2);
    let total = old.len().checked_add(additional).ok_or(Fault::Overflow)?;
    if total > limit {
        return Err(Fault::TooLarge.into());
    }
    let mut value = Vec::new();
    value
        .try_reserve_exact(total)
        .map_err(|_| Fault::Capacity)?;
    value.extend_from_slice(old);
    if let Some(t) = trusted {
        if !value.is_empty() && !value.ends_with(b";") {
            value.push(b';')
        }
        value.extend_from_slice(t.as_bytes());
        value.push(b';')
    }
    config.set_value(section, key, Some(&value))?;
    Ok(())
}
impl<'id, 'slots> System<'id, 'slots> {
    /// Actually allocate unique home/ports and produce a complete duplicate of the
    /// caller's loaded official CONFIG. Any refusal releases all newly reserved
    /// ports, but permanently burns its path number. Input template stays unchanged.
    pub fn configuration_create(
        &mut self,
        template: &Configuration,
    ) -> Result<Generated<'id>, Failure> {
        self.directory.check()?;
        if self.attempts == self.options.limits.configurations {
            return Err(Fault::Capacity.into());
        }
        let bytes = zeroize::Zeroizing::new(template.serialize()?);
        if bytes.len() > self.options.limits.configuration_bytes {
            return Err(Fault::TooLarge.into());
        }
        drop(bytes);
        let needed = required_ports(template, self.options.limits.ports_per_configuration)?;
        let id = self.core.allocate_path()?;
        self.attempts += 1;
        self.directory.counter(self.core.path_high_water())?;
        let home = self.directory.path.join(id.number().to_string());
        if home.as_os_str().as_bytes().len() > self.options.limits.path_bytes {
            return Err(Fault::TooLarge.into());
        }
        // The counter is actually durable before any numbered home/config is exposed.
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(needed)
            .map_err(|_| Fault::Capacity)?;
        DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .map_err(|e| Failure::io("create configuration home", &home, e))?;
        let outcome: Result<Configuration, Failure> = (|| {
            let mut config = template.duplicate()?;
            let default = home.join("config");
            let path = default.as_os_str().as_bytes();
            config.set_value(b"PATHS", b"DEFAULTCONFIG", Some(path))?;
            config.set_value(b"arm", b"CONFIG", Some(path))?;
            config.set_value(b"PATHS", b"GNUNET_HOME", Some(home.as_os_str().as_bytes()))?;
            for (section, key, _) in template.entries() {
                if key.eq_ignore_ascii_case(b"PORT") {
                    let original = template.get_number(section, key)?;
                    if original > u64::from(u16::MAX) {
                        return Err(Fault::InvalidInput.into());
                    }
                    if original == 0 {
                        continue;
                    }
                    let single = single_key(section, self.options.limits.configuration_bytes)?;
                    if template.get_yesno(b"testing", &single).unwrap_or(false) {
                        let mut count = Vec::new();
                        count
                            .try_reserve_exact(
                                section.len().checked_add(13).ok_or(Fault::Overflow)?,
                            )
                            .map_err(|_| Fault::Capacity)?;
                        count.extend_from_slice(b"num_");
                        count.extend_from_slice(section);
                        count.extend_from_slice(b"_per_host");
                        if template.get_number(b"testing", &count).is_ok_and(|n| n > 0) {
                            return Err(Cause::SharedServiceSharding.into());
                        }
                        continue;
                    }
                    if ports.len() == self.options.limits.ports_per_configuration {
                        return Err(Fault::Capacity.into());
                    }
                    let port = self.reserve_port()?;
                    ports.push(port);
                    config.set_number(section, key, u64::from(port.port()))?;
                } else if key.eq_ignore_ascii_case(b"UNIXPATH") {
                    let single = single_key(section, self.options.limits.configuration_bytes)?;
                    if template.get_yesno(b"testing", &single).unwrap_or(false) {
                        continue;
                    }
                    if section.is_empty()
                        || section.iter().any(|b| matches!(b, 0 | b'/' | b'\\'))
                        || section == b"."
                        || section == b".."
                    {
                        return Err(Fault::InvalidInput.into());
                    }
                    let mut filename =
                        std::ffi::OsString::from(std::ffi::OsStr::from_bytes(section));
                    filename.push(".sock");
                    let socket = home.join(filename);
                    let bytes = socket.as_os_str().as_bytes();
                    if bytes.len() > self.options.limits.path_bytes {
                        return Err(Fault::TooLarge.into());
                    }
                    socket2::SockAddr::unix(&socket)
                        .map_err(|e| Failure::io("validate generated UNIXPATH", &socket, e))?;
                    config.set_value(section, key, Some(bytes))?;
                } else if key.eq_ignore_ascii_case(b"HOSTNAME") {
                    let host = self.options.hostname.as_deref().unwrap_or(b"localhost");
                    config.set_value(section, key, Some(host))?;
                }
            }
            for section in template.sections() {
                let section = section.name();
                if config.get(section, b"ADVERTISED_PORT").is_some()
                    && !ignored(&config, section, b"ADVERTISED_PORT")
                    && let Some(port) = config.get(section, b"PORT")
                {
                    let port = copied(port, self.options.limits.configuration_bytes)?;
                    config.set_value(section, b"ADVERTISED_PORT", Some(&port))?;
                }
                append_acl(
                    &mut config,
                    section,
                    self.options.trusted_ip.as_deref(),
                    self.options.limits.configuration_bytes,
                )?;
            }
            config.set_value(b"nat", b"USE_LOCALADDR", Some(b"YES"))?;
            let encoded = zeroize::Zeroizing::new(config.serialize()?);
            if encoded.len() > self.options.limits.configuration_bytes {
                return Err(Fault::TooLarge.into());
            }
            Ok(config)
        })();
        match outcome {
            Ok(configuration) => Ok(Generated {
                id,
                home,
                configuration,
                ports,
            }),
            Err(mut failure) => {
                for port in ports {
                    if let Err(e) = self.core.release(port) {
                        failure.add(Cause::Protocol(e));
                    }
                }
                match std::fs::remove_dir(&home) {
                    Ok(()) => {}
                    Err(e) => failure.add(Cause::Io {
                        operation: "remove failed configuration home",
                        path: home,
                        error: e,
                    }),
                }
                Err(failure)
            }
        }
    }
}

/// Exact non-shared nonzero PORT fields in a loaded template, for caller pool
/// sizing before any native directory/socket effect. Values remain opaque.
pub fn required_ports(template: &Configuration, limit: usize) -> Result<usize, Failure> {
    let mut count = 0usize;
    for (section, key, _) in template.entries() {
        if !key.eq_ignore_ascii_case(b"PORT") {
            continue;
        }
        let value = template.get_number(section, key)?;
        if value > u64::from(u16::MAX) {
            return Err(Fault::InvalidInput.into());
        }
        if value == 0 {
            continue;
        }
        let single = single_key(section, 4096)?;
        if template.get_yesno(b"testing", &single).unwrap_or(false) {
            continue;
        }
        count = count.checked_add(1).ok_or(Fault::Overflow)?;
        if count > limit {
            return Err(Fault::Capacity.into());
        }
    }
    Ok(count)
}
