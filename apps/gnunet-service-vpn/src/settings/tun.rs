//! Native VPN device selection and the resources required by each owner.
use super::{LOCAL, text};
use crate::Failure;
use gnunet_config::Configuration;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "macos")]
pub(crate) enum Utun {
    Automatic,
    Named { name: String, unit: u32 },
}

pub(crate) struct Fresh {
    #[cfg(target_os = "macos")]
    pub utun: Utun,
    #[cfg(not(target_os = "macos"))]
    pub name: String,
    #[cfg(target_os = "freebsd")]
    pub checkpoint: PathBuf,
    #[cfg(target_os = "linux")]
    pub helper: PathBuf,
    #[cfg(target_os = "linux")]
    pub helper_partial: Duration,
    #[cfg(target_os = "linux")]
    pub override_mtu: bool,
}

#[cfg(target_os = "macos")]
impl Fresh {
    pub(crate) const fn utun_unit(&self) -> Option<u32> {
        match &self.utun {
            Utun::Automatic => None,
            Utun::Named { unit, .. } => Some(*unit),
        }
    }
}

pub(crate) enum TunMode {
    Fresh(Fresh),
    #[cfg(unix)]
    Preopened {
        expected: Option<String>,
    },
    #[cfg(windows)]
    Existing {
        name: String,
    },
}

impl TunMode {
    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::Fresh(_) => "Fresh",
            #[cfg(unix)]
            Self::Preopened { .. } => "Preopened",
            #[cfg(windows)]
            Self::Existing { .. } => "Existing",
        }
    }

    pub(super) fn read(c: &Configuration) -> Result<Self, Failure> {
        let mode = text(c, LOCAL, b"TUN_MODE")?.unwrap_or("fresh");
        if c.get(LOCAL, b"TUN_RECOVERY_FILE").is_some()
            && (!cfg!(target_os = "freebsd") || mode != "fresh")
        {
            return Err("TUN_RECOVERY_FILE requires fresh FreeBSD TUN ownership".into());
        }
        let name = text(c, b"vpn", b"IFNAME")?;
        if let Some(name) = name {
            validate_name(name)?;
        }
        match mode {
            "fresh" => Ok(Self::Fresh(Fresh {
                #[cfg(target_os = "macos")]
                utun: match name {
                    None => Utun::Automatic,
                    Some(name) => {
                        let unit = name
                            .strip_prefix("utun")
                            .filter(|suffix| {
                                (*suffix == "0" || !suffix.starts_with('0'))
                                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
                            })
                            .and_then(|suffix| suffix.parse::<u32>().ok())
                            .filter(|unit| *unit < u32::MAX)
                            .ok_or("macOS fresh mode requires [vpn] IFNAME=utunN when specified")?;
                        Utun::Named {
                            name: name.to_owned(),
                            unit,
                        }
                    }
                },
                #[cfg(not(target_os = "macos"))]
                name: name.unwrap_or("vpn-gnunet").to_owned(),
                #[cfg(target_os = "freebsd")]
                checkpoint: checkpoint(c)?,
                #[cfg(target_os = "linux")]
                helper: c.suid_binary_path(b"gnunet-helper-vpn")?,
                #[cfg(target_os = "linux")]
                helper_partial: helper_timeout(c)?,
                #[cfg(target_os = "linux")]
                override_mtu: c.get(LOCAL, b"MTU").is_some(),
            })),
            #[cfg(unix)]
            "preopened" => Ok(Self::Preopened {
                expected: name.map(str::to_owned),
            }),
            #[cfg(windows)]
            "existing" => Ok(Self::Existing {
                name: name.unwrap_or("vpn-gnunet").to_owned(),
            }),
            _ => Err("invalid native TUN_MODE for this platform".into()),
        }
    }

    pub(crate) fn expected_name(&self) -> Option<&str> {
        match self {
            Self::Fresh(fresh) => {
                #[cfg(target_os = "macos")]
                match &fresh.utun {
                    Utun::Automatic => None,
                    Utun::Named { name, .. } => Some(name),
                }
                #[cfg(not(target_os = "macos"))]
                Some(&fresh.name)
            }
            #[cfg(unix)]
            Self::Preopened { expected } => expected.as_deref(),
            // The native open qualifies the adapter by its GUID/LUID/index.
            #[cfg(windows)]
            Self::Existing { .. } => None,
        }
    }
}

#[cfg(unix)]
fn validate_name(name: &str) -> Result<(), Failure> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err("invalid official [vpn] IFNAME".into());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_name(name: &str) -> Result<(), Failure> {
    if name.is_empty() || name.contains('\0') || name.encode_utf16().count() > 256 {
        return Err("invalid Windows [vpn] IFNAME".into());
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn checkpoint(c: &Configuration) -> Result<PathBuf, Failure> {
    use gnunet_config::ProcessEnvironment;
    if c.get(LOCAL, b"TUN_RECOVERY_FILE").is_some() {
        return Ok(c.get_absolute_filename(LOCAL, b"TUN_RECOVERY_FILE", &ProcessEnvironment)?);
    }
    c.expand_absolute_filename(b"${GNUNET_DATA_HOME}/vpn/tun-recovery", &ProcessEnvironment)
        .map_err(|error| format!("FreeBSD TUN recovery requires an absolute [vpn-rust] TUN_RECOVERY_FILE or GNUNET_DATA_HOME: {error}").into())
}

#[cfg(target_os = "linux")]
fn helper_timeout(c: &Configuration) -> Result<Duration, Failure> {
    let key = b"HELPER_INPUT_TIMEOUT";
    let micros = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(5_000_000);
    let timeout = Duration::from_micros(micros);
    if micros == 0 || micros == u64::MAX || std::time::Instant::now().checked_add(timeout).is_none()
    {
        return Err("VPN timer must be finite, nonzero and representable".into());
    }
    Ok(timeout)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn staged_vpn_uses_the_kernel_assigned_utun_unless_named() -> Result<(), Failure> {
        let mut c = Configuration::default();
        c.set_value(LOCAL, b"TUN_MODE", Some(b"fresh"))?;
        if !matches!(
            TunMode::read(&c)?,
            TunMode::Fresh(Fresh {
                utun: Utun::Automatic
            })
        ) {
            return Err("unnamed macOS VPN did not select automatic utun".into());
        }
        c.set_value(b"vpn", b"IFNAME", Some(b"utun4"))?;
        if TunMode::read(&c)?.expected_name() != Some("utun4") {
            return Err("explicit utun constraint was lost".into());
        }
        c.set_value(b"vpn", b"IFNAME", Some(b"utun04"))?;
        if TunMode::read(&c).is_ok() {
            return Err("accepted a name that cannot match the native interface".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn recovery_path_requires_freebsd_fresh_ownership() -> Result<(), Failure> {
        let mut c = Configuration::default();
        c.set_value(
            LOCAL,
            b"TUN_RECOVERY_FILE",
            Some(b"/tmp/private-vpn/tun-recovery"),
        )?;
        #[cfg(unix)]
        let mode: &[u8] = b"preopened";
        #[cfg(windows)]
        let mode: &[u8] = b"existing";
        c.set_value(LOCAL, b"TUN_MODE", Some(mode))?;
        if TunMode::read(&c).is_ok() {
            return Err("borrowed VPN accepted an administrative recovery checkpoint".into());
        }
        c.set_value(LOCAL, b"TUN_MODE", Some(b"fresh"))?;
        #[cfg(target_os = "freebsd")]
        if !matches!(TunMode::read(&c)?, TunMode::Fresh(fresh) if fresh.checkpoint == std::path::Path::new("/tmp/private-vpn/tun-recovery"))
        {
            return Err("FreeBSD lost the selected recovery path".into());
        }
        #[cfg(not(target_os = "freebsd"))]
        if TunMode::read(&c).is_ok() {
            return Err("another platform accepted a FreeBSD VPN recovery checkpoint".into());
        }
        Ok(())
    }
}
