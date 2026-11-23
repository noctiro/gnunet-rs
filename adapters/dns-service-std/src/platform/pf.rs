//! Automatic PF route-to policy within an administrator-delegated anchor.
mod command;
mod coverage;
mod journal;
mod monitor;
mod rules;
mod scope;
mod topology;
pub(super) use scope::Scope;
pub(super) use topology::Topology;
#[cfg(any(test, target_os = "freebsd"))]
mod states;
use super::Options;
use command::{Output, Runner};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
const UTILITY: &str = "/sbin/pfctl";
const LEASE: &str = "/var/run/gnunet-dns-rust-pf.lock";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Reserved,
    Recovering,
    Prepared,
    Recording,
    Attempted,
    Installed,
    Retired,
}
#[derive(Debug, Default)]
pub(super) struct Cleanup {
    pub retirement: Option<io::Error>,
    pub policy: Option<io::Error>,
}
impl Cleanup {
    pub fn is_empty(&self) -> bool {
        self.retirement.is_none() && self.policy.is_none()
    }
}
pub(super) struct Controls {
    lock: File,
    lease: PathBuf,
    program: PathBuf,
    runner: Runner,
    state: State,
    label: String,
    canonical: Vec<u8>,
}
fn require_success(output: Output) -> io::Result<Vec<u8>> {
    if output.status.success() {
        Ok(output.bytes)
    } else {
        Err(io::Error::other(format!(
            "PF control exited with {}",
            output.status
        )))
    }
}
fn fresh_label() -> io::Result<String> {
    let mut generation = [0; 16];
    gnunet_native::entropy::fill(&mut generation)?;
    let mut label = String::from("gnunet-rs-dns-");
    for byte in generation {
        use std::fmt::Write;
        write!(&mut label, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(label)
}
impl Controls {
    /// Reserve only the dedicated namespace, before interface creation.
    pub fn reserve() -> io::Result<Self> {
        let program = Path::new(UTILITY);
        let metadata = program.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PF utility must be executable and root-owned without group/world write permission",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(LEASE)?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PF original lease file policy",
            ));
        }
        lock.try_lock().map_err(io::Error::other)?;
        // The lease name must survive a crash before any journaled PF mutation.
        File::open("/var/run")?.sync_all()?;
        let (state, label, canonical) = match journal::read(&lock)? {
            Some(policy) => (State::Recovering, policy.label, policy.canonical),
            None => (State::Reserved, fresh_label()?, Vec::new()),
        };
        let runner = Runner::leased(&lock)?;
        let owner = Self {
            lock,
            lease: PathBuf::from(LEASE),
            program: program.to_owned(),
            runner,
            state,
            label,
            canonical,
        };
        Ok(owner)
    }
    pub async fn prepare(&mut self) -> io::Result<()> {
        if self.state == State::Recovering {
            // This happens before allocating a new TUN. Cancellation leaves
            // the saved original policy in the same controller for cleanup.
            self.retire_policy().await?;
            self.label = fresh_label()?;
            self.canonical.clear();
            self.state = State::Reserved;
        }
        if self.state != State::Reserved {
            return Err(io::Error::other(
                "PF namespace preparation already consumed",
            ));
        }
        let status = self.query(&["-s", "info"]).await?;
        monitor::require_enabled(&status)?;
        let root = self.query(&["-s", "rules"]).await?;
        if !rules::root_delegates(&root) {
            return Err(io::Error::other(
                "PF root must begin with the delegated gnunet-rs/dns anchor",
            ));
        }
        let before = self.query(&["-a", rules::ANCHOR, "-s", "rules"]).await?;
        let children = self.query(&["-a", rules::ANCHOR, "-s", "Anchors"]).await?;
        if !rules::trim(&before).is_empty() || !rules::trim(&children).is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "PF DNS anchor contains preexisting or unresolved policy",
            ));
        }
        self.interface_coverage(None, None).await?;
        self.state = State::Prepared;
        Ok(())
    }
    async fn query(&mut self, args: &[&str]) -> io::Result<Vec<u8>> {
        require_success(self.runner.run(&self.program, args, &[]).await?)
    }
    fn lease_current(&self) -> io::Result<()> {
        let original = self.lock.metadata()?;
        let current = std::fs::symlink_metadata(&self.lease)?;
        if !current.is_file()
            || original.nlink() != 1
            || current.dev() != original.dev()
            || current.ino() != original.ino()
        {
            return Err(io::Error::other("PF original lease namespace changed"));
        }
        Ok(())
    }
    async fn interface_coverage(
        &mut self,
        actual_interface: Option<&str>,
        hard: Option<tokio::time::Instant>,
    ) -> io::Result<scope::Scope> {
        let until = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(3))
            .ok_or_else(|| io::Error::other("PF interface coverage deadline overflow"))?;
        let until = hard.map_or(until, |hard| until.min(hard));
        // Down interfaces also belong to the scope: their addresses can become
        // usable without another PF installation when a link comes back up.
        let native = scope::Scope::new(gnunet_native::interfaces::snapshot(Default::default())?)?;
        let listing = require_success(
            self.runner
                .observe_until(&self.program, &["-v", "-s", "Interfaces"], until)
                .await?,
        )?;
        let coverage = coverage::Coverage::parse(&listing)?;
        for name in native.names() {
            coverage.require(name)?;
        }
        if let Some(interface) = actual_interface {
            coverage.require(interface.as_bytes())?;
        }
        if tokio::time::Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF interface coverage exceeded its original deadline",
            ));
        }
        Ok(native)
    }
    pub async fn install(
        &mut self,
        options: &Options,
        actual_interface: &str,
        gid: u32,
    ) -> io::Result<Scope> {
        if self.state != State::Prepared {
            return Err(io::Error::other("PF policy intent already used"));
        }
        let input = rules::render(
            actual_interface,
            options.ipv4,
            options.ipv6,
            gid,
            &self.label,
        )?;
        let canonical = require_success(
            self.runner
                .run(
                    &self.program,
                    &["-n", "-v", "-o", "none", "-a", rules::ANCHOR, "-f", "-"],
                    input.as_bytes(),
                )
                .await?,
        )?;
        if !rules::owned(&canonical, &self.label) {
            return Err(io::Error::other(
                "PF parser did not return the exact owned rule set",
            ));
        }
        self.canonical = canonical;
        let root = self.query(&["-s", "rules"]).await?;
        let before = self.query(&["-a", rules::ANCHOR, "-s", "rules"]).await?;
        let children = self.query(&["-a", rules::ANCHOR, "-s", "Anchors"]).await?;
        if !rules::root_delegates(&root)
            || !rules::trim(&before).is_empty()
            || !rules::trim(&children).is_empty()
        {
            return Err(io::Error::other(
                "PF delegation changed before policy admission",
            ));
        }
        self.interface_coverage(Some(actual_interface), None)
            .await?;
        self.lease_current()?;
        self.state = State::Recording;
        journal::store(&mut self.lock, &self.label, &self.canonical)?;
        self.state = State::Attempted;
        require_success(
            self.runner
                .run(
                    &self.program,
                    &["-o", "none", "-a", rules::ANCHOR, "-f", "-"],
                    input.as_bytes(),
                )
                .await?,
        )?;
        let loaded = self.query(&["-a", rules::ANCHOR, "-s", "rules"]).await?;
        if !rules::owned(&loaded, &self.label) || loaded != self.canonical {
            return Err(io::Error::other(
                "PF installed rules did not retain the original owner labels",
            ));
        }
        let root = self.query(&["-s", "rules"]).await?;
        if !rules::root_delegates(&root) {
            return Err(io::Error::other(
                "PF DNS delegation changed after policy installation",
            ));
        }
        let scope = self.retire_dns_states(actual_interface).await?;
        self.state = State::Installed;
        Ok(scope)
    }
    async fn retire_dns_states(&mut self, actual_interface: &str) -> io::Result<scope::Scope> {
        // One original allowance includes interface observation, the complete
        // selection snapshot, every precise kill and full-table ID readback.
        let hard = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(10))
            .ok_or_else(|| io::Error::other("PF DNS state deadline overflow"))?;
        let original = scope::Scope::new(gnunet_native::interfaces::snapshot(Default::default())?)?;
        let local = original.ip_addresses()?;
        #[cfg(target_os = "freebsd")]
        {
            let targets = self
                .selected_states(states::Selection::Dns(local), hard)
                .await?;
            if !targets.is_empty() {
                let mut owner = gnunet_native::pf_freebsd::StateKiller::open(hard.into_std())?;
                for target in &targets {
                    self.lease_current()?;
                    // A state can close between selection and its exact-ID
                    // operation. The independent readback still checks it.
                    let _removed = target.retire(&mut owner)?;
                    tokio::task::yield_now().await;
                }
                self.lease_current()?;
                if !self
                    .selected_states(states::Selection::Original(targets), hard)
                    .await?
                    .is_empty()
                {
                    return Err(io::Error::other(
                        "original DNS PF state retirement unconfirmed",
                    ));
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut states = gnunet_native::pf::DnsStates::select(
                &local,
                hard.into_std(),
                gnunet_native::pf::Limits::default(),
            )?;
            loop {
                self.lease_current()?;
                if !states.retire_next()? {
                    break;
                }
            }
            self.lease_current()?;
            states.finish()?;
        }
        // A new address can carry previously unselected state. It cannot adopt
        // this sweep merely because its interface currently has PF enabled.
        let current = self.observe(actual_interface, hard).await?;
        original.require_same(&current)?;
        Ok(current)
    }
    #[cfg(target_os = "freebsd")]
    async fn selected_states(
        &mut self,
        selection: states::Selection,
        hard: tokio::time::Instant,
    ) -> io::Result<Vec<states::Id>> {
        let (status, targets) = self
            .runner
            .states(
                &self.program,
                &["-v", "-v", "-s", "states"],
                selection,
                hard,
            )
            .await?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "PF state query exited with {status}"
            )));
        }
        Ok(targets)
    }
    pub async fn cleanup(&mut self) -> Cleanup {
        let mut report = Cleanup {
            retirement: self.runner.retire().await.err(),
            policy: None,
        };
        if !self.runner.idle() {
            return report;
        }
        if matches!(
            self.state,
            State::Reserved | State::Prepared | State::Retired
        ) {
            return report;
        }
        report.policy = self.retire_policy().await.err();
        report
    }
    async fn retire_policy(&mut self) -> io::Result<()> {
        self.lease_current()?;
        if self.state == State::Recording {
            // No mutating command was admitted when journal publication failed.
            journal::clear(&self.lock)?;
            self.state = State::Retired;
            return Ok(());
        }
        let current = self.query(&["-a", rules::ANCHOR, "-s", "rules"]).await?;
        let children = self.query(&["-a", rules::ANCHOR, "-s", "Anchors"]).await?;
        if !rules::trim(&children).is_empty()
            || (!rules::trim(&current).is_empty()
                && (!rules::owned(&current, &self.label) || current != self.canonical))
        {
            return Err(io::Error::other(
                "PF DNS anchor changed; foreign or uncertain rules were left intact",
            ));
        }
        if !rules::trim(&current).is_empty() {
            self.lease_current()?;
            self.query(&["-a", rules::ANCHOR, "-F", "rules"]).await?;
            let after = self.query(&["-a", rules::ANCHOR, "-s", "rules"]).await?;
            let children = self.query(&["-a", rules::ANCHOR, "-s", "Anchors"]).await?;
            if !rules::trim(&after).is_empty() || !rules::trim(&children).is_empty() {
                return Err(io::Error::other("PF DNS anchor removal unconfirmed"));
            }
        }
        self.lease_current()?;
        journal::clear(&self.lock)?;
        self.state = State::Retired;
        Ok(())
    }
}
