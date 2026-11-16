//! Actual original-interface DAD samples, with no device-retaining background job.
use super::*;
use gnunet_native::wintun::{DadState, Family, InterfacePort};
pub(super) struct Backend {
    port: InterfacePort,
}
impl Backend {
    pub(super) fn source(&self) -> io::Result<bool> {
        match self.port.interface() {
            Ok(_) => Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotConnected | io::ErrorKind::NotFound
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    pub(super) fn begin(&mut self) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn close(self) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn poll(
        &mut self,
        _: &mut Context<'_>,
        target: &Ipv6Target,
    ) -> Poll<io::Result<Step>> {
        Poll::Ready((|| {
            // ERROR_NOT_FOUND is absence only after the exact original interface
            // and IPv6 family have both been requalified. Other errors survive.
            let state = match self.port.find_address(target.address.into())? {
                Some(row) if row.prefix != target.prefix => Ipv6State::PrefixMismatch {
                    observed: row.prefix,
                },
                Some(row) => match row.dad {
                    DadState::Preferred => Ipv6State::Ready,
                    DadState::Tentative => Ipv6State::Tentative,
                    DadState::Duplicate => Ipv6State::DadFailed,
                    DadState::Deprecated => Ipv6State::Deprecated,
                    DadState::Invalid => Ipv6State::Invalid,
                    DadState::Other(native) => Ipv6State::Unknown { native },
                },
                None => Ipv6State::Missing,
            };
            // Windows DAD states are not Unix address flags.
            Ok(Step::Sample(state, None))
        })())
    }
}
impl OwnedTun {
    /// Observe the exact address/prefix and actual Windows DAD state. The job
    /// keeps no native session/adapter/DLL alive and does not change an address.
    pub fn watch_ipv6(
        &self,
        address: Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: Ipv6WatchOptions,
    ) -> io::Result<Ipv6Watch> {
        options.validate()?;
        if prefix > 128 {
            return Err(invalid("IPv6 prefix overflow"));
        }
        if !self.epoch.current() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        tokio::runtime::Handle::try_current()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let port = self.session().adapter().port();
        port.interface()?;
        port.ip_interface(Family::V6)?;
        let target = Ipv6Target {
            epoch: self.epoch(),
            interface: self.info.clone(),
            address,
            prefix,
            deadline: until,
        };
        initialize(target, Backend { port }, options)
    }
}
