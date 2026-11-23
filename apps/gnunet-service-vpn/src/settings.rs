//! Official VPN keys plus explicit bounded local resource/exit selection policy.
use crate::Failure;
use gnunet_config::Configuration;
#[cfg(windows)]
use gnunet_service_runtime::LocalListenerAccess;
#[cfg(windows)]
use gnunet_service_runtime::credentials::UnixAccess;
use gnunet_vpn_host::{coordinator::DiscoveryMode, startup::ServiceSettings};

mod tun;
pub(super) use tun::TunMode;

const LOCAL: &[u8] = b"vpn-rust";
fn text<'a>(c: &'a Configuration, section: &[u8], key: &[u8]) -> Result<Option<&'a str>, Failure> {
    c.get(section, key)
        .map(std::str::from_utf8)
        .transpose()
        .map_err(Into::into)
}
#[cfg(windows)]
fn local_access(c: &Configuration, policy: UnixAccess) -> Result<LocalListenerAccess, Failure> {
    use LocalListenerAccess::{Everyone, Group, Owner};
    let required = LocalListenerAccess::from(policy);
    let access = match text(c, LOCAL, b"LOCAL_ACCESS")? {
        None if required == Group => Group,
        None | Some("owner") => Owner,
        Some("group") => Group,
        Some("everyone") => Everyone,
        Some(_) => return Err("LOCAL_ACCESS must be owner, group or everyone".into()),
    };
    Ok(access)
}
pub(super) struct Settings {
    pub mode: TunMode,
    #[cfg(windows)]
    pub wintun: crate::device::windows::Settings,
    pub service: ServiceSettings,
    pub resolver: gnunet_resolver_broker::Limits,
    #[cfg(windows)]
    pub local_access: LocalListenerAccess,
}
impl Settings {
    #[cfg(windows)]
    pub(super) fn direct_local_access(
        &self,
        config: &Configuration,
    ) -> Result<LocalListenerAccess, Failure> {
        if config.get(b"vpn", b"UNIXPATH").is_some()
            && !self.local_access.satisfies(self.service.unix)
        {
            return Err("[vpn-rust] LOCAL_ACCESS cannot satisfy [vpn] UNIX_MATCH_UID/GID".into());
        }
        Ok(self.local_access)
    }

    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let service = ServiceSettings::read(c, DiscoveryMode::External)?;
        let mode = TunMode::read(c)?;
        let resolver = gnunet_resolver_broker::Limits::default();
        Ok(Self {
            mode,
            #[cfg(windows)]
            wintun: crate::device::windows::Settings::read(c)?,
            #[cfg(windows)]
            local_access: local_access(c, service.unix)?,
            service,
            resolver,
        })
    }
}
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn windows_local_access_obeys_service_restrictions() -> Result<(), Failure> {
        let mut config = Configuration::default();
        config.set_value(LOCAL, b"WINTUN_DLL", Some(br"C:\GNUnet\wintun.dll"))?;
        if Settings::read(&config)?.local_access != LocalListenerAccess::Owner {
            return Err("VPN default local access changed".into());
        }
        config.set_value(b"vpn", b"UNIX_MATCH_GID", Some(b"YES"))?;
        let group = Settings::read(&config)?;
        if group.local_access != LocalListenerAccess::Group || !group.service.unix.match_gid {
            return Err("VPN did not select group access".into());
        }
        config.set_value(LOCAL, b"LOCAL_ACCESS", Some(b"everyone"))?;
        let tcp_only = Settings::read(&config)?;
        tcp_only.direct_local_access(&config)?;
        config.set_value(b"vpn", b"UNIXPATH", Some(br"C:\GNUnet\vpn.sock"))?;
        if Settings::read(&config)?
            .direct_local_access(&config)
            .is_ok()
        {
            return Err("VPN accepted unrestricted access with group matching".into());
        }
        config.set_value(b"vpn", b"UNIX_MATCH_UID", Some(b"YES"))?;
        config.set_value(LOCAL, b"LOCAL_ACCESS", Some(b"group"))?;
        if Settings::read(&config)?
            .direct_local_access(&config)
            .is_ok()
        {
            return Err("VPN accepted group access with owner matching".into());
        }
        config.set_value(LOCAL, b"LOCAL_ACCESS", Some(b"owner"))?;
        let owner = Settings::read(&config)?;
        if owner.local_access != LocalListenerAccess::Owner || !owner.service.unix.match_uid {
            return Err("VPN did not preserve owner access precedence".into());
        }
        Ok(())
    }
}
