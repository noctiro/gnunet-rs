//! Shared read-only configuration rules; observations never create cleanup rights.
use super::{QueryFailure, SnapshotFailure};
use crate::{Failure, settings::Settings};
use gnunet_tun_host::{
    Action, Ipv4Observation, NativeSnapshot, RouteQueryCompletion, RouteQueryOutcome, Version,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::time::Instant;
#[derive(Clone, Copy)]
pub(super) struct RouteKey {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
}
pub(super) struct Plan {
    mtu: u32,
    ipv4: Option<(Ipv4Addr, Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub routes: Vec<RouteKey>,
}
impl Plan {
    #[cfg(windows)]
    pub fn creation_action(&self, index: usize) -> Option<Action> {
        match index {
            0 => self.ipv4.map(|_| Action::IpMtu {
                version: Version::V4,
                bytes: self.mtu,
            }),
            1 => self.ipv6.map(|_| Action::IpMtu {
                version: Version::V6,
                bytes: self.mtu,
            }),
            2 => self
                .ipv4
                .map(|(address, _, _)| Action::Ipv4Address(address)),
            3 => self.ipv4.map(|(_, mask, _)| Action::Ipv4Netmask(mask)),
            4 => self
                .ipv6
                .map(|(address, prefix)| Action::Ipv6Address { address, prefix }),
            5 => Some(Action::LinkUp(true)),
            _ => None,
        }
    }
    #[cfg(windows)]
    pub fn creation_route(&self, index: usize) -> Option<Action> {
        let connected = usize::from(self.ipv4.is_some()) + usize::from(self.ipv6.is_some());
        self.routes.get(index + connected).map(|key| Action::Route {
            add: true,
            destination: key.destination,
            prefix: key.prefix,
            gateway: key.gateway,
        })
    }
    pub fn new(settings: &Settings) -> Result<Self, Failure> {
        let mut routes = Vec::new();
        routes.try_reserve_exact(
            settings
                .routes
                .len()
                .checked_add(2)
                .ok_or(gnunet_types::Error::Overflow)?,
        )?;
        if let Some((address, mask, bits)) = settings.ipv4 {
            routes.push(RouteKey {
                destination: IpAddr::V4((u32::from(address) & u32::from(mask)).into()),
                prefix: bits,
                gateway: None,
            });
        }
        if let Some((address, bits)) = settings.ipv6 {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            routes.push(RouteKey {
                destination: IpAddr::V6((u128::from(address) & mask).into()),
                prefix: bits,
                gateway: None,
            });
        }
        for action in &settings.routes {
            match action {
                Action::Route {
                    destination,
                    prefix,
                    gateway,
                    ..
                } => routes.push(RouteKey {
                    destination: *destination,
                    prefix: *prefix,
                    gateway: *gateway,
                }),
                _ => return Err("EXIT route observation expects Route action".into()),
            }
        }
        Ok(Self {
            mtu: settings.mtu,
            ipv4: settings.ipv4,
            ipv6: settings.ipv6,
            routes,
        })
    }
    pub fn options(&self) -> gnunet_tun_host::SnapshotOptions {
        gnunet_tun_host::SnapshotOptions {
            ipv4: self.ipv4.is_some(),
            ipv6: self.ipv6.is_some(),
        }
    }
    pub fn snapshot(
        &self,
        snapshot: NativeSnapshot,
        helper: bool,
    ) -> Result<NativeSnapshot, Failure> {
        let v4 = self.ipv4.is_none_or(|(address, mask, _)| {
            snapshot.ipv4_address() == Ipv4Observation::Present(address)
                && snapshot.ipv4_netmask() == Ipv4Observation::Present(mask)
        });
        if !snapshot.up()
            || !v4
            || snapshot.close_error().is_some()
            || (!helper
                && (self.ipv4.is_some() && snapshot.ip_mtu(Version::V4) != Some(self.mtu)
                    || self.ipv6.is_some() && snapshot.ip_mtu(Version::V6) != Some(self.mtu)))
        {
            return Err(Box::new(SnapshotFailure(snapshot)));
        }
        Ok(snapshot)
    }
}
pub(super) fn route(
    done: RouteQueryCompletion,
    until: Instant,
) -> Result<RouteQueryCompletion, Failure> {
    if !matches!(done.outcome(), RouteQueryOutcome::Exact(_))
        || done.write_error().is_some()
        || done.close_error().is_some()
        || done.observed_at() >= until
    {
        return Err(Box::new(QueryFailure(done)));
    }
    Ok(done)
}
