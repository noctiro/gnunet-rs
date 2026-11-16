//! Read-only periodic verification of the original installed interception policy.
use super::{Controls, State, require_success, rules, scope::Scope};
use std::{io, time::Duration};
use tokio::time::Instant;

// Five fixed control queries per cycle, with no overlapping probe or backlog.
const INTERVAL: Duration = Duration::from_secs(5);
const ALLOWANCE: Duration = Duration::from_secs(3);

pub(super) fn require_enabled(status: &[u8]) -> io::Result<()> {
    let mut values = status
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"Status:"));
    let enabled = values.next().is_some_and(|value| {
        value
            .split(|byte| byte.is_ascii_whitespace())
            .find(|word| !word.is_empty())
            == Some(b"Enabled".as_slice())
    });
    if !enabled || values.next().is_some() {
        return Err(io::Error::other(
            "PF must remain enabled by the administrator",
        ));
    }
    Ok(())
}

impl Controls {
    async fn query_until(&mut self, args: &[&str], hard: Instant) -> io::Result<Vec<u8>> {
        require_success(self.runner.observe_until(&self.program, args, hard).await?)
    }

    pub(super) async fn observe(&mut self, interface: &str, hard: Instant) -> io::Result<Scope> {
        if Instant::now() >= hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF original policy observation was not polled within its allowance",
            ));
        }
        self.lease_current()?;
        require_enabled(&self.query_until(&["-s", "info"], hard).await?)?;
        if !rules::root_delegates(&self.query_until(&["-s", "rules"], hard).await?) {
            return Err(io::Error::other("PF original DNS delegation changed"));
        }
        let current = self
            .query_until(&["-a", rules::ANCHOR, "-s", "rules"], hard)
            .await?;
        if current != self.canonical {
            return Err(io::Error::other("PF original canonical DNS rules changed"));
        }
        drop(current);
        let children = self
            .query_until(&["-a", rules::ANCHOR, "-s", "Anchors"], hard)
            .await?;
        if !rules::trim(&children).is_empty() {
            return Err(io::Error::other(
                "PF original DNS anchor gained child policy",
            ));
        }
        drop(children);
        let scope = self.interface_coverage(Some(interface), Some(hard)).await?;
        self.lease_current()?;
        if Instant::now() >= hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF original policy observation deadline expired",
            ));
        }
        Ok(scope)
    }

    pub(in crate::platform) async fn watch(&mut self, interface: &str) -> io::Result<()> {
        if self.state != State::Installed || self.scope.is_none() {
            return Err(io::Error::other("PF original installed scope is missing"));
        }
        loop {
            let next = Instant::now()
                .checked_add(INTERVAL)
                .ok_or_else(|| io::Error::other("PF observation interval overflow"))?;
            let hard = next
                .checked_add(ALLOWANCE)
                .ok_or_else(|| io::Error::other("PF observation deadline overflow"))?;
            tokio::time::sleep_until(next).await;
            let current = self.observe(interface, hard).await?;
            self.scope
                .as_ref()
                .ok_or_else(|| io::Error::other("PF original installed scope disappeared"))?
                .require_same(&current)?;
        }
    }
}

#[cfg(test)]
mod tests;
