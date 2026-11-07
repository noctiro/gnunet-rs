//! Complete active TESTBED native system/configuration library. Native effects
//! are explicit synchronous utility calls, never performed inside a socket poll.
#![cfg(unix)]
#![forbid(unsafe_code)]
pub use gnunet_testbed as core;
use gnunet_types::Error as Fault;
use std::{
    ffi::OsString,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
mod configuration;
mod directory;
mod probe;
mod types;
pub use configuration::{Generated, required_ports};
pub use types::*;
/// Caller-driven native system; the caller owns fixed logical reservation slots.
/// No child process, daemon, key loader, socket server, or hidden task exists.
pub struct System<'id, 'slots> {
    core: core::System<'id, 'slots>,
    directory: directory::Directory,
    options: Options,
    attempts: usize,
}
impl<'id, 'slots> System<'id, 'slots> {
    /// Create only an empty/new or exact Rust-marked directory. Prefix is explicit;
    /// callers may pass GNUNET_TESTBED_PREFIX, never an implicit C home importer.
    pub fn create(
        instance: &'id core::Instance,
        slots: &'slots mut [core::PortSlot],
        options: Options,
    ) -> Result<Self, Failure> {
        options.limits.validate()?;
        if !options.families.ipv4 && !options.families.ipv6 {
            return Err(Fault::InvalidInput.into());
        }
        configuration::validate_options(&options)?;
        let mut resource =
            core::System::new(instance, slots, options.low_port, options.high_port, 0)?;
        let (directory, high) = directory::Directory::create(&options, resource.allocation())?;
        // No path is issued before the actual persisted counter is loaded. Rebuild
        // with a fresh checked original allocation; no token escaped this temporary.
        resource.close();
        drop(resource);
        let resource =
            core::System::new(instance, slots, options.low_port, options.high_port, high)?;
        Ok(Self {
            core: resource,
            directory,
            options,
            attempts: 0,
        })
    }
    /// Actual owned root. Reading a path does not prove a peer was started there.
    pub fn directory(&self) -> &Path {
        &self.directory.path
    }
    /// Probe actual wildcard TCP/UDP endpoints and logically reserve the returned
    /// number. Probe FDs are closed before return: future kernel exclusivity and
    /// peer/service readiness are deliberately not asserted.
    pub fn reserve_port(&mut self) -> Result<core::Reservation<'id>, Failure> {
        self.directory.check()?;
        loop {
            let probe = self.core.probe()?;
            match probe::available(probe.port(), self.options.families) {
                Ok(free) => {
                    if let Some(reservation) = self.core.probed(
                        probe,
                        if free {
                            core::Availability::Free
                        } else {
                            core::Availability::Busy
                        },
                    )? {
                        return Ok(reservation);
                    }
                }
                Err(mut failure) => {
                    if let Err(e) = self.core.cancel_probe(probe) {
                        failure.add(Cause::Protocol(e));
                    }
                    return Err(failure);
                }
            }
        }
    }
    /// Release an exact logical reservation. No process termination is implied.
    pub fn release_port(&mut self, port: core::Reservation<'id>) -> Result<(), Failure> {
        self.core.release(port)?;
        Ok(())
    }
    /// Actual complete local publication under the caller's explicit replace policy.
    pub fn write_configuration(
        &mut self,
        generated: &Generated<'id>,
        path: &Path,
        replace: Replace,
    ) -> Result<Published, Failure> {
        self.core.check_path(generated.id)?;
        for p in &generated.ports {
            self.core.reserved(*p)?;
        }
        if path.as_os_str().as_bytes().len() > self.options.limits.path_bytes {
            return Err(Fault::TooLarge.into());
        }
        let bytes = zeroize::Zeroizing::new(generated.configuration.serialize()?);
        if bytes.len() > self.options.limits.configuration_bytes {
            return Err(Fault::TooLarge.into());
        }
        self.directory.publish(path, &bytes, replace)
    }
    /// Release every original reservation. Existing config paths remain, and any
    /// actual peers using them remain the caller's responsibility.
    pub fn release_configuration(&mut self, generated: &mut Generated<'id>) -> Result<(), Failure> {
        self.core.check_path(generated.id)?;
        let mut failure: Option<Failure> = None;
        for p in generated.ports.drain(..) {
            if let Err(e) = self.core.release(p) {
                if let Some(f) = failure.as_mut() {
                    f.add(Cause::Protocol(e))
                } else {
                    failure = Some(Failure::from(e))
                }
            }
        }
        if let Some(f) = failure {
            Err(f)
        } else {
            Ok(())
        }
    }
    /// Stop logical admission, close original lock after independently requested
    /// actual owned-directory removal. No peer shutdown/quiescence is manufactured.
    pub fn destroy(mut self, remove_paths: bool) -> Result<Removal, Failure> {
        self.core.close();
        self.directory.remove(remove_paths)
    }
    /// Original native lock observation for diagnostics; no startup/readiness proof.
    pub fn has_root_lock(&self) -> bool {
        self.directory.locked()
    }
}
