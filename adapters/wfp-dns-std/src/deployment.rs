//! Explicit, native deployment of the signed GNUnet WFP driver package.
//! The package owns its original bytes through verification and native calls.
mod package;
mod service;
mod trust;

use crate::device::{Maintenance, MaintenanceError};
use crate::{InstallationReceipt, ProvisionLimits, Provisioner};
use gnunet_wfp_dns::device::maintenance::{Phase, Progress};
use package::{Architecture, Package};
use service::{Access, Installed, Manager};
use std::{
    io,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Devices::DeviceAndDriverInstallation::{DiInstallDriverW, DiUninstallDriverW},
        System::{
            SystemInformation::{IMAGE_FILE_MACHINE_UNKNOWN, OSVERSIONINFOW},
            Threading::{GetCurrentProcess, IsWow64Process2},
        },
    },
};

/// Source INF, SYS and catalog held open after native package verification.
/// Dropping this object closes its handles and makes no Windows policy changes.
pub struct VerifiedPackage {
    package: Package,
    architecture: Architecture,
}

/// A successful installation call and its immediate follow-up observation.
#[derive(Debug)]
pub enum InstallOutcome {
    /// Windows requested a restart. Inspect the installation after that restart.
    RestartRequired,
    /// The original packages were matched and the service status was inspected.
    Installed(Installation),
}

/// Published Driver Store package and the fixed service's current SCM status.
#[derive(Debug)]
pub struct Installation {
    /// Fully qualified Windows-published INF path.
    pub published_inf: PathBuf,
    /// Actual status returned by SCM.
    pub state: DriverState,
}

/// The fixed driver's latest SCM state. Capturing DNS requires the later
/// service-file START with the original upstream sockets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverState {
    /// SCM reported a stopped driver and these native status fields.
    Stopped {
        /// SCM's Win32 exit value.
        win32: u32,
        /// The service's own exit value, when applicable.
        specific: u32,
    },
    /// SCM says the driver is starting.
    StartPending,
    /// SCM says the driver is stopping.
    StopPending,
    /// SCM reports an active kernel service.
    Running,
    /// Another native SCM state code.
    Other(u32),
}

/// Observed results of explicitly requesting driver start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartOutcome {
    /// This request succeeded and SCM reported running.
    Running,
    /// SCM already reported running. The image on disk is matched to the
    /// configuration and the service was left in its existing state.
    AlreadyRunning,
    /// SCM reports that a start is pending.
    StartPending,
}

/// Observed driver rundown or SCM stop progress for the verified installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    /// Native rundown still owns resources. Repeat an explicit stop operation.
    RundownPending(Progress),
    /// SCM reports a pending start or stop.
    Pending(DriverState),
    /// SCM reports the service stopped.
    Stopped {
        /// SCM's Win32 exit value.
        win32: u32,
        /// The service's own exit value, when applicable.
        specific: u32,
    },
}

/// Observed removal of the exact stopped package or its pending native state.
#[derive(Debug)]
pub enum RemoveOutcome {
    /// SCM still reports a start or stop in progress. No removal was attempted.
    Pending(DriverState),
    /// Windows requested a restart after accepting the package removal.
    RestartRequired {
        /// Original Windows-published INF path for follow-up inspection.
        published_inf: PathBuf,
    },
    /// SCM and the original installation paths report absence.
    Removed {
        /// Original Windows-published INF path that was removed.
        published_inf: PathBuf,
    },
}

impl VerifiedPackage {
    /// Bind the fixed three package files on the native Windows architecture
    /// and verify both package members with the Windows driver trust policy.
    /// Requires Windows build 19041 or newer. Trust checks use cached chain data.
    ///
    /// # Errors
    /// Returns validation, native trust or namespace errors before mutation.
    pub fn open(directory: &Path) -> io::Result<Self> {
        let architecture = platform()?;
        let package = Package::open(directory, &architecture)?;
        trust::verify(&package)?;
        Ok(Self {
            package,
            architecture,
        })
    }

    /// Install the verified primitive driver with Windows' default selection
    /// flags. A pre-existing service is a collision. Installation and subsequent
    /// start are separate operator actions. Keep other privileged installers
    /// and SCM configuration edits serialized with this operation.
    ///
    /// # Errors
    /// An install call error can follow partial native changes. Errors after
    /// install acceptance identify the failed observation without attempting
    /// rollback or replacement.
    pub fn install(&self) -> io::Result<InstallOutcome> {
        let manager = Manager::open()?;
        if manager.service(Access::Query)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "GNUnetDnsIntercept already exists. Inspect the installed package before any replacement",
            ));
        }
        if install_inf(&self.package.inf.path)? {
            return Ok(InstallOutcome::RestartRequired);
        }
        self.inspect_with(&manager).map(InstallOutcome::Installed).map_err(|error| {
            io::Error::other(format!("Windows accepted driver installation. Installed package inspection failed: {error}"))
        })
    }

    /// Observe the published INF and SCM status after binding both the Driver
    /// Store package and SCM binary configuration to the verified source.
    ///
    /// # Errors
    /// Reports missing, different, inaccessible or malformed installed state.
    pub fn inspect(&self) -> io::Result<Installation> {
        self.inspect_with(&Manager::open()?)
    }

    fn inspect_with(&self, manager: &Manager) -> io::Result<Installation> {
        self.bind(manager, Access::Query)?.observe()
    }

    fn bind(&self, manager: &Manager, access: Access) -> io::Result<Installed> {
        let installed = manager.service(access)?.ok_or(io::ErrorKind::NotFound)?;
        installed.bind(&self.package, &self.architecture)
    }

    /// Explicitly start the bound Windows kernel service after verifying the
    /// exact original persistent WFP metadata receipt.
    ///
    /// # Errors
    /// Refuses a mismatched package or policy. Observes actual SCM acceptance
    /// and preserves errors from the follow-up status query independently.
    pub fn start(&self, receipt: InstallationReceipt) -> io::Result<StartOutcome> {
        let mut engine = Provisioner::open(ProvisionLimits::default()).map_err(io::Error::other)?;
        let policy = engine.verify(receipt);
        let closed = engine.close();
        if let Err(error) = policy {
            return Err(io::Error::other(format!(
                "{error}. WFP engine close {closed:?}"
            )));
        }
        if closed.has_failure() {
            return Err(io::Error::other(format!("WFP engine close {closed:?}")));
        }
        self.bind(&Manager::open()?, Access::Start)?.start()
    }

    /// Advance native rundown, then request SCM stop using the same verified
    /// installation and this call's actual native retirement and close receipt.
    /// Stop the GNUnet DNS data service before calling this operation. Native
    /// finalization and the SCM call can block in Windows. Serialize privileged
    /// changes to the fixed SCM service and Driver Store with this operation.
    ///
    /// # Errors
    /// Preserves original native or SCM failures. After handoff, a later call
    /// can obtain a terminal observation from the still-loaded protected
    /// device. SCM stop still requires closing that original handle.
    pub fn stop(&self) -> io::Result<StopOutcome> {
        let installed = self.bind(&Manager::open()?, Access::Stop)?;
        match installed.state()? {
            DriverState::Stopped { win32, specific } => {
                return Ok(StopOutcome::Stopped { win32, specific });
            }
            state @ (DriverState::StartPending | DriverState::StopPending) => {
                return Ok(StopOutcome::Pending(state));
            }
            DriverState::Other(state) => {
                return Err(io::Error::other(format!(
                    "SCM driver cannot stop from state {state}"
                )));
            }
            DriverState::Running => {}
        }
        let mut rundown = match Maintenance::open() {
            Ok(rundown) => rundown,
            Err(original @ MaintenanceError::Open { .. }) => {
                let released = Maintenance::recover_release().map_err(|observation| {
                    io::Error::other(format!(
                        "{original}. Terminal native retirement observation failed: {observation}"
                    ))
                })?;
                return installed.stop(released);
            }
            Err(error) => return Err(io::Error::other(error)),
        };
        let mut progress = rundown.poll().map_err(io::Error::other)?;
        if matches!(
            progress.phase,
            Phase::PreparedForNativeWait | Phase::Completion
        ) {
            progress = rundown.finalize().map_err(io::Error::other)?;
        }
        match progress.phase {
            Phase::NativeRetired => installed.stop(rundown.close().map_err(io::Error::other)?),
            Phase::Failed => Err(io::Error::other(format!(
                "Windows driver rundown failed with NTSTATUS {:#010x}",
                progress.status.cast_unsigned()
            ))),
            _ => Ok(StopOutcome::RundownPending(progress)),
        }
    }

    /// Remove the exact verified primitive driver package after observing SCM
    /// stopped. The verification source must be a separate copy. Keep other
    /// privileged SCM and Driver Store operations serialized until return.
    ///
    /// # Errors
    /// Refuses unidentified, running or unexpected service state. A Windows
    /// removal error can follow partial changes. Errors after acceptance
    /// identify which follow-up observation could not confirm removal.
    pub fn remove(&self) -> io::Result<RemoveOutcome> {
        let manager = Manager::open()?;
        let installed = self.bind(&manager, Access::Query)?;
        match installed.state()? {
            state @ (DriverState::StartPending | DriverState::StopPending) => {
                return Ok(RemoveOutcome::Pending(state));
            }
            DriverState::Stopped { .. } => {}
            state => {
                return Err(io::Error::other(format!(
                    "SCM must report the verified WFP driver stopped before removal, observed {state:?}"
                )));
            }
        }
        let removal = installed.release_for_removal(&self.package)?;
        if uninstall_inf(removal.published_wide())? {
            return Ok(RemoveOutcome::RestartRequired {
                published_inf: removal.into_published(),
            });
        }
        let published_inf = removal.confirm(&manager).map_err(|error| {
            io::Error::other(format!(
                "Windows accepted WFP package removal. Follow-up inspection failed: {error}"
            ))
        })?;
        Ok(RemoveOutcome::Removed { published_inf })
    }
}

#[expect(
    unsafe_code,
    reason = "Read the native Windows version and architecture using fixed initialized outputs"
)]
fn platform() -> io::Result<Architecture> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..OSVERSIONINFOW::default()
    };
    // SAFETY: OSVERSIONINFOW gives the native structure version and exact initialized size.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        return Err(trust::native("RtlGetVersion", status));
    }
    if (
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    ) < (10, 0, 19041)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WFP deployment requires Windows build 19041 or newer",
        ));
    }
    let mut process = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: current process's pseudo-handle remains live. Both outputs are writable machine words.
    if unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } == 0 {
        return Err(trust::last_error("IsWow64Process2"));
    }
    if process != IMAGE_FILE_MACHINE_UNKNOWN {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WFP deployment requires the native Windows executable",
        ));
    }
    Architecture::new(native)
}

#[expect(
    unsafe_code,
    reason = "Install the pinned verified INF through Microsoft's primitive driver API"
)]
fn install_inf(path: &[u16]) -> io::Result<bool> {
    let mut reboot = 0;
    // SAFETY: path is the NUL-terminated full path from the private package constructor.
    // A nonnull reboot output keeps restart under the caller's control. Zero flags never force selection.
    if unsafe { DiInstallDriverW(ptr::null_mut(), path.as_ptr(), 0, &mut reboot) } == 0 {
        let error = trust::last_error("DiInstallDriverW");
        return Err(io::Error::other(format!(
            "{error}. Inspect Windows for partial installation before retrying"
        )));
    }
    Ok(reboot != 0)
}

#[expect(
    unsafe_code,
    reason = "Remove the exact previously bound primitive driver through Microsoft's SDK"
)]
fn uninstall_inf(path: &[u16]) -> io::Result<bool> {
    let mut reboot = 0;
    // SAFETY: the stopped installation owner supplies its verified NUL-terminated
    // Windows-published INF path. Zero selects the default uninstall operation.
    // The original reboot output keeps system restart under operator control.
    if unsafe { DiUninstallDriverW(ptr::null_mut(), path.as_ptr(), 0, &mut reboot) } == 0 {
        let error = trust::last_error("DiUninstallDriverW");
        return Err(io::Error::other(format!(
            "{error}. Inspect Windows for partial removal before retrying"
        )));
    }
    Ok(reboot != 0)
}
