//! Local SCM and Windows Driver Store observations for the original package.
use super::package::{Architecture, IMAGE_NAME, Package, invalid, local_absolute, wide_path};
use super::trust::last_error;
use super::{DriverState, StopOutcome};
use crate::device::Released;
use gnunet_native::paths::{FileIdentity, system_directory};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io,
    mem::size_of,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::{
        SetupGetInfDriverStoreLocationW, SetupGetInfPublishedNameW,
    },
    Foundation::ERROR_SERVICE_DOES_NOT_EXIST,
    System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
    },
};
use windows_sys::core::w;

struct Handle(SC_HANDLE);

impl Drop for Handle {
    #[expect(
        unsafe_code,
        reason = "This is the one original live SCM handle transferred by a successful SDK open"
    )]
    fn drop(&mut self) {
        // SAFETY: the private owner closes exactly once, without granting mutation.
        let _closed = unsafe { CloseServiceHandle(self.0) };
    }
}

pub(super) struct Manager(Handle);

pub(super) enum Access {
    Query,
    Start,
    Stop,
}

impl Manager {
    #[expect(
        unsafe_code,
        reason = "Open the standard local SCM database without opening a remote connection"
    )]
    pub(super) fn open() -> io::Result<Self> {
        // SAFETY: null names select the local active database. The success handle is owned.
        let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if raw.is_null() {
            Err(last_error("OpenSCManagerW"))
        } else {
            Ok(Self(Handle(raw)))
        }
    }

    #[expect(
        unsafe_code,
        reason = "Open the one fixed service with query rights and one explicit mutation right"
    )]
    pub(super) fn service(&self, access: Access) -> io::Result<Option<Service>> {
        let rights = SERVICE_QUERY_CONFIG
            | SERVICE_QUERY_STATUS
            | match access {
                Access::Query => 0,
                Access::Start => SERVICE_START,
                Access::Stop => SERVICE_STOP,
            };
        // SAFETY: the manager is live and the service name is a terminated static string.
        let raw = unsafe { OpenServiceW(self.0.0, w!("GNUnetDnsIntercept"), rights) };
        if !raw.is_null() {
            return Ok(Some(Service(Handle(raw))));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            Ok(None)
        } else {
            Err(super::trust::native(
                "OpenServiceW",
                error.raw_os_error().unwrap_or_default(),
            ))
        }
    }
}

pub(super) struct Service(Handle);

impl Service {
    pub(super) fn bind(
        self,
        package: &Package,
        architecture: &Architecture,
    ) -> io::Result<Installed> {
        let image = self.image()?;
        let system = system_directory()?;
        let store_root = fs::canonicalize(system.join("DriverStore").join("FileRepository"))?;
        let resolved = fs::canonicalize(&image)?;
        let parent = resolved
            .parent()
            .ok_or_else(|| invalid("SCM image has no package directory"))?;
        if parent.parent() != Some(store_root.as_path())
            || !resolved
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(OsStr::new(IMAGE_NAME)))
        {
            return Err(invalid(
                "SCM image is outside the native WFP Driver Store package",
            ));
        }
        let installed = Package::open(parent, architecture)?;
        // SCM paths can use \SystemRoot while SetupAPI publishes a DOS path. Compare original
        // file IDs independently of the spelling. Keep the actual installed package pinned.
        if FileIdentity::of(&File::open(image)?)? != FileIdentity::of(&installed.image.file)?
            || !package.same_bytes(&installed)?
        {
            return Err(invalid("SCM does not name the verified WFP package image"));
        }
        let published = published_inf(&installed)?;
        Ok(Installed {
            service: self,
            package: installed,
            published,
        })
    }

    #[expect(
        unsafe_code,
        reason = "SCM writes a bounded aligned native record and the returned path is decoded within that record"
    )]
    fn image(&self) -> io::Result<PathBuf> {
        // QueryServiceConfigW documents a maximum 8192-byte native buffer.
        #[repr(align(8))]
        struct Storage([u8; 8192]);
        let mut buffer = Storage([u8::MAX; 8192]);
        let base = buffer.0.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        let mut needed = 0;
        // SAFETY: aligned initialized 8 KiB buffer and one live original service handle.
        if unsafe { QueryServiceConfigW(self.0.0, base, buffer.0.len() as u32, &mut needed) } == 0 {
            return Err(last_error("QueryServiceConfigW"));
        }
        // SAFETY: success initializes a QUERY_SERVICE_CONFIGW at the aligned start.
        let config = unsafe { &*base };
        if config.dwServiceType != SERVICE_KERNEL_DRIVER
            || config.dwStartType != SERVICE_DEMAND_START
            || config.dwErrorControl != SERVICE_ERROR_NORMAL
        {
            return Err(invalid(
                "SCM service does not have the canonical WFP driver type and start policy",
            ));
        }
        let start = config
            .lpBinaryPathName
            .addr()
            .checked_sub(base.addr())
            .filter(|offset| *offset >= size_of::<QUERY_SERVICE_CONFIGW>() && offset % 2 == 0)
            .ok_or_else(|| invalid("SCM image path pointer is outside the configuration buffer"))?;
        let bytes = buffer
            .0
            .get(start..)
            .ok_or_else(|| invalid("SCM image path is outside the configuration buffer"))?;
        let (words, _) = bytes.as_chunks::<2>();
        let wide = words
            .iter()
            .copied()
            .map(u16::from_ne_bytes)
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        if wide.is_empty() || wide.len() == words.len() {
            return Err(invalid("SCM image path is missing or unterminated"));
        }
        image_path(&wide)
    }

    #[expect(
        unsafe_code,
        reason = "SCM writes one exact initialized status structure for this original service handle"
    )]
    fn status(&self) -> io::Result<DriverState> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        // SAFETY: live service, exact output record size and initialized size-output word.
        if unsafe {
            QueryServiceStatusEx(
                self.0.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(last_error("QueryServiceStatusEx"));
        }
        Ok(match status.dwCurrentState {
            SERVICE_STOPPED => DriverState::Stopped {
                win32: status.dwWin32ExitCode,
                specific: status.dwServiceSpecificExitCode,
            },
            SERVICE_START_PENDING => DriverState::StartPending,
            SERVICE_STOP_PENDING => DriverState::StopPending,
            SERVICE_RUNNING => DriverState::Running,
            other => DriverState::Other(other),
        })
    }

    #[expect(
        unsafe_code,
        reason = "StartServiceW receives the verified original fixed-service handle and no arguments"
    )]
    fn start(&self) -> io::Result<()> {
        // SAFETY: caller retains its package-binding proof, no arguments or backing pointers.
        if unsafe { StartServiceW(self.0.0, 0, ptr::null()) } == 0 {
            return Err(last_error("StartServiceW"));
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "Request SCM stop on this exact fixed driver service and one initialized native status record"
    )]
    fn request_stop(&self) -> io::Result<()> {
        let mut last = SERVICE_STATUS::default();
        // SAFETY: the original service handle and initialized writable status
        // record remain live through this synchronous native control request.
        if unsafe { ControlService(self.0.0, SERVICE_CONTROL_STOP, &mut last) } == 0 {
            return Err(last_error("ControlService(SERVICE_CONTROL_STOP)"));
        }
        Ok(())
    }
}

pub(super) struct Installed {
    service: Service,
    package: Package,
    published: PathBuf,
}

impl Installed {
    pub(super) fn state(&self) -> io::Result<DriverState> {
        self.service.status()
    }

    pub(super) fn observe(self) -> io::Result<super::Installation> {
        Ok(super::Installation {
            published_inf: self.published,
            state: self.service.status()?,
        })
    }

    pub(super) fn start(&self) -> io::Result<super::StartOutcome> {
        use DriverState as Status;
        match self.service.status()? {
            Status::Running => return Ok(super::StartOutcome::AlreadyRunning),
            Status::StartPending => return Ok(super::StartOutcome::StartPending),
            Status::StopPending => return Err(io::Error::other("SCM driver stop is pending")),
            Status::Other(state) => {
                return Err(io::Error::other(format!(
                    "SCM service cannot start from state {state}"
                )));
            }
            Status::Stopped { .. } => {}
        }
        self.service.start()?;
        let status = self.service.status().map_err(|error| {
            io::Error::other(format!(
                "SCM accepted start. The follow-up status observation failed: {error}"
            ))
        })?;
        match status {
            Status::Running => Ok(super::StartOutcome::Running),
            Status::StartPending => Ok(super::StartOutcome::StartPending),
            Status::StopPending => Err(io::Error::other(
                "SCM accepted start and then reported a pending stop",
            )),
            Status::Stopped { win32, specific } => Err(io::Error::other(format!(
                "SCM accepted start and then reported stop with Win32 {win32:#010x}, service status {specific:#010x}"
            ))),
            Status::Other(state) => Err(io::Error::other(format!(
                "SCM accepted start and then reported state {state}"
            ))),
        }
    }

    pub(super) fn stop(&self, _released: Released) -> io::Result<StopOutcome> {
        match self.state()? {
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
        self.service.request_stop().map_err(|error| {
            io::Error::other(format!(
                "Native WFP rundown succeeded. SCM stop request failed: {error}"
            ))
        })?;
        let state = self.state().map_err(|error| {
            io::Error::other(format!(
                "SCM accepted stop. Follow-up status observation failed: {error}"
            ))
        })?;
        match state {
            DriverState::Stopped { win32, specific } => {
                Ok(StopOutcome::Stopped { win32, specific })
            }
            state @ DriverState::StopPending => Ok(StopOutcome::Pending(state)),
            state => Err(io::Error::other(format!(
                "SCM accepted stop and then reported {state:?}"
            ))),
        }
    }

    pub(super) fn release_for_removal(self, source: &Package) -> io::Result<Removal> {
        for (source, installed) in [
            (&source.inf, &self.package.inf),
            (&source.image, &self.package.image),
            (&source.catalog, &self.package.catalog),
        ] {
            if FileIdentity::of(&source.file)? == FileIdentity::of(&installed.file)? {
                return Err(invalid("WFP removal requires a separate verification copy"));
            }
        }
        // Re-observe the original published INF and current status while the
        // read pins and SCM service handle are still live.
        if published_inf(&self.package)? != self.published {
            return Err(invalid(
                "the original WFP published INF changed before removal",
            ));
        }
        if !matches!(self.state()?, DriverState::Stopped { .. }) {
            return Err(io::Error::other(
                "SCM no longer reports the verified WFP driver stopped",
            ));
        }
        // These installed pins cannot accompany a path-based Windows deletion.
        // The separate verification source stays pinned in the caller.
        let published_wide = wide_path(&self.published)?;
        let installed_inf = read_setup_path(&self.package.inf.path)?;
        Ok(Removal {
            published: self.published,
            published_wide,
            installed_inf,
        })
    }
}

pub(super) struct Removal {
    published: PathBuf,
    published_wide: Vec<u16>,
    installed_inf: PathBuf,
}

impl Removal {
    pub(super) fn published_wide(&self) -> &[u16] {
        &self.published_wide
    }

    pub(super) fn into_published(self) -> PathBuf {
        self.published
    }

    pub(super) fn confirm(self, manager: &Manager) -> io::Result<PathBuf> {
        for path in [&self.published, &self.installed_inf] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(format!(
                        "original WFP INF remains at {}",
                        path.display()
                    )));
                }
            }
        }
        if manager.service(Access::Query)?.is_some() {
            return Err(io::Error::other("the SCM WFP service entry remains"));
        }
        Ok(self.published)
    }
}

fn image_path(wide: &[u16]) -> io::Result<PathBuf> {
    let wide = wide
        .strip_prefix(&[34])
        .and_then(|tail| tail.strip_suffix(&[34]))
        .unwrap_or(wide);
    if wide.contains(&34) {
        return Err(invalid("SCM image path contains unexpected quotes"));
    }
    let starts = |prefix: &[u8]| {
        wide.get(..prefix.len()).is_some_and(|head| {
            head.iter().zip(prefix).all(|(&left, &right)| {
                u8::try_from(left).is_ok_and(|left| left.eq_ignore_ascii_case(&right))
            })
        })
    };
    for prefix in [b"\\SystemRoot\\".as_slice(), b"%SystemRoot%\\"] {
        if starts(prefix) {
            let system = system_directory()?;
            let root = system
                .parent()
                .ok_or_else(|| invalid("system directory has no Windows root"))?;
            let suffix = PathBuf::from(OsString::from_wide(&wide[prefix.len()..]));
            if suffix.is_absolute() || suffix.has_root() {
                return Err(invalid("SCM system-root image is not relative to Windows"));
            }
            return local_absolute(&root.join(suffix));
        }
    }
    let wide = if starts(b"\\??\\") { &wide[4..] } else { wide };
    local_absolute(Path::new(&OsString::from_wide(wide)))
}

#[expect(
    unsafe_code,
    reason = "SetupAPI receives pinned input paths and initialized bounded native output buffers"
)]
fn published_inf(installed: &Package) -> io::Result<PathBuf> {
    let mut published = [u16::MAX; 260];
    // SAFETY: the retained package owns the terminated INF input for this synchronous call.
    if unsafe {
        SetupGetInfPublishedNameW(
            installed.inf.path.as_ptr(),
            published.as_mut_ptr(),
            published.len() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error("SetupGetInfPublishedNameW"));
    }
    let published = read_setup_path(&published)?;
    validate_published_inf(&published)?;
    let published_wide = wide_path(&published)?;
    let mut location = [u16::MAX; 260];
    // SAFETY: the published input is exactly NUL terminated, and both outputs are initialized.
    if unsafe {
        SetupGetInfDriverStoreLocationW(
            published_wide.as_ptr(),
            ptr::null(),
            ptr::null(),
            location.as_mut_ptr(),
            location.len() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error("SetupGetInfDriverStoreLocationW"));
    }
    let location = read_setup_path(&location)?;
    if FileIdentity::of(&File::open(location)?)? != FileIdentity::of(&installed.inf.file)? {
        return Err(invalid(
            "the published INF resolves to another Driver Store package",
        ));
    }
    Ok(published)
}

fn validate_published_inf(path: &Path) -> io::Result<()> {
    let system = system_directory()?;
    let windows = system
        .parent()
        .ok_or_else(|| invalid("system directory has no Windows root"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("published INF has no directory"))?;
    if !path.file_name().is_some_and(is_oem_inf)
        || fs::canonicalize(parent)? != fs::canonicalize(windows.join("INF"))?
    {
        return Err(invalid(
            "WFP deployment requires a published Windows OEM INF",
        ));
    }
    Ok(())
}

fn is_oem_inf(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        let name = name.as_bytes();
        name.len() > 7
            && name[..3].eq_ignore_ascii_case(b"oem")
            && name[name.len() - 4..].eq_ignore_ascii_case(b".inf")
            && name[3..name.len() - 4].iter().all(u8::is_ascii_digit)
    })
}

fn read_setup_path(wide: &[u16]) -> io::Result<PathBuf> {
    let end = wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len());
    if end == 0 || end == wide.len() {
        return Err(invalid("SetupAPI returned an invalid terminated path"));
    }
    local_absolute(Path::new(&OsString::from_wide(&wide[..end])))
}
