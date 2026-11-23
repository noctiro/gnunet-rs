//! CreateProcessW with exact application paths and per-launch handle allowlists.
use super::{AccountProfile, PrimaryToken, ProfileCleanup, environment};
use crate::{
    identity::{PrivateSecurityDescriptor, Sid},
    paths::absolute_wide_path,
    socket_activation::{
        ACCOUNT_HANDLE_PREFIX, AccountExportSection, Admission, Delivery, ExportSection,
    },
    stdio::Stdio,
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::OpenOptions,
    io,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr,
    sync::{Arc, Mutex},
};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
static INHERITANCE: Mutex<()> = Mutex::new(());

/// Native process launch bounds. Limits count input UTF-16 units and resource
/// slots; allocator metadata and spare capacity are not resident-memory receipts.
#[derive(Clone, Copy, Debug)]
pub struct LaunchLimits {
    /// Complete encoded command line, including its terminating NUL; at most 32767.
    pub command_units: usize,
    /// Input environment units before duplicate-name elimination.
    pub environment_units: usize,
    /// Maximum explicit plus generated environment entries.
    pub environment_entries: usize,
    /// Maximum arguments after the executable name.
    pub arguments: usize,
    /// Three standard slots plus explicitly exported kernel handles.
    pub handles: usize,
}
impl Default for LaunchLimits {
    fn default() -> Self {
        Self {
            command_units: 32767,
            environment_units: 1024 * 1024,
            environment_entries: 4096,
            arguments: 4096,
            handles: 256,
        }
    }
}
/// Console ownership selected explicitly at native creation.
#[derive(Clone, Copy, Debug, Default)]
pub enum Console {
    /// Preserve the parent's console relationship.
    #[default]
    Inherit,
    /// Start a new console process group without fabricating POSIX signals.
    NewProcessGroup,
    /// Detach from the parent's console; readiness remains a separate operation.
    Detached,
}
/// An explicitly duplicated kernel handle, advertised as hexadecimal text to
/// this child only. This is not a Winsock-socket duplication API.
pub struct ExportedHandle<'a> {
    /// Caller-owned original kernel object.
    pub handle: BorrowedHandle<'a>,
    /// Child environment key. Generated exports override explicit environment
    /// entries of the same native case-insensitive name; duplicate exports fail.
    pub environment_key: &'a OsStr,
}
/// Complete explicit launch inputs. No shell, PATH lookup, mutable global
/// environment or current-directory change is introduced by this boundary.
pub struct Spawn<'a> {
    /// Absolute native executable filename, independent of argument quoting.
    pub executable: &'a Path,
    /// Literal argv0, independent of the executable filename. Windows CRT argv0
    /// cannot contain a quote or NUL; other native UTF-16 units are retained.
    pub argv0: &'a OsStr,
    /// Literal arguments after argv0, encoded with Windows CRT quoting rules.
    pub arguments: &'a [OsString],
    /// Explicit child environment; duplicate names use their last input value.
    pub environment: &'a [(OsString, OsString)],
    /// Absolute child working directory.
    pub directory: &'a Path,
    /// stdin, stdout and stderr, in that order.
    pub stdio: [Stdio<'a>; 3],
    /// Additional caller-owned kernel resources; only private launch copies inherit.
    pub exported_handles: &'a [ExportedHandle<'a>],
    /// Native console relationship, not service readiness or target-account selection.
    pub console: Console,
}
pub(super) struct ProcessObject {
    pub(super) handle: OwnedHandle,
    pub(super) id: u32,
}
/// Original process handle and diagnostic PID returned by successful native
/// creation. Drop closes a handle only: it never terminates or waits for a child.
/// No method reconstructs authority from a PID or infers service readiness.
pub struct Process(pub(super) Arc<ProcessObject>);
/// Read-only pin of one original process object. It can qualify a connected
/// bootstrap peer after an exit observation, but grants no wait or termination
/// action and proves neither current liveness nor service readiness.
#[derive(Clone)]
pub struct ProcessIdentity(Arc<ProcessObject>);
impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessIdentity")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}
impl ProcessIdentity {
    pub(crate) fn matches(&self, process: &Process) -> bool {
        Arc::ptr_eq(&self.0, &process.0)
    }

    /// Pin this current process with a real independently owned handle. The
    /// current-process pseudo-handle is never adopted as an owned/borrowed handle.
    #[expect(
        unsafe_code,
        reason = "DuplicateHandle copies the current-process pseudo-handle into one real owned handle; scalar outputs are initialized and immediately adopted on success"
    )]
    pub fn current() -> io::Result<Self> {
        let mut handle = ptr::null_mut();
        // SAFETY: the pseudo-handle is a valid API input, output storage is live,
        // and no other owner is created for the returned real handle.
        let copied = unsafe {
            let current = GetCurrentProcess();
            DuplicateHandle(
                current,
                current,
                current,
                &mut handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if copied == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful DuplicateHandle returned a unique real handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        // SAFETY: this scalar observation requires no borrowed storage.
        let id = unsafe { GetCurrentProcessId() };
        Ok(Self(Arc::new(ProcessObject { handle, id })))
    }
    /// Qualify this connected named-pipe server's kernel-reported client against
    /// the pinned original process. No PID is opened/reconstructed. Keeping the
    /// original process object prevents reuse of its PID for a replacement.
    pub fn matches_pipe_client(&self, server: BorrowedHandle<'_>) -> io::Result<bool> {
        Ok(crate::pipe::client_process_id(server)? == self.0.id)
    }
}
impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}
impl AsHandle for Process {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.handle.as_handle()
    }
}
impl Process {
    /// Lend read-only original-object identity for bootstrap qualification. The
    /// lease may retain this handle after the registry releases its own owner.
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity(Arc::clone(&self.0))
    }
    /// Diagnostic original PID; the process handle remains the actual authority.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.0.id
    }
    /// Nonblocking observation of this original process. Exit code 259 is a valid
    /// completed code when the kernel wait is signaled, never a running sentinel.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        status(&self.0)
    }
    /// Request forced termination of this original process with the supplied
    /// unsigned exit code. Success is a request receipt, not observed termination.
    #[expect(
        unsafe_code,
        reason = "TerminateProcess borrows the original owned process handle; no PID lookup or owner transfer occurs"
    )]
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: the original process handle remains live for this native call.
        if unsafe { TerminateProcess(self.0.handle.as_raw_handle(), exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "A zero-time kernel wait determines actual exit before the original process handle's exit code is read"
)]
pub(super) fn status(process: &ProcessObject) -> io::Result<Option<u32>> {
    // SAFETY: original live process handle, zero timeout, no retained borrow.
    match unsafe { WaitForSingleObject(process.handle.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => Ok(None),
        WAIT_OBJECT_0 => {
            let mut code = 0;
            // SAFETY: exact writable scalar output for this already signaled process.
            if unsafe { GetExitCodeProcess(process.handle.as_raw_handle(), &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(code))
        }
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected process wait result",
        )),
    }
}
#[expect(
    unsafe_code,
    reason = "DuplicateHandle copies one live borrowed kernel handle into a uniquely owned noninheritable handle in this same process"
)]
fn duplicate(handle: BorrowedHandle<'_>) -> io::Result<OwnedHandle> {
    let mut output = ptr::null_mut();
    // SAFETY: source remains borrowed; output is an independent local handle.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle(),
            GetCurrentProcess(),
            &mut output,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful DuplicateHandle transferred exactly one owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(output) })
}
#[expect(
    unsafe_code,
    reason = "GetStdHandle returns a borrowed native slot; only a successful DuplicateHandle result is owned and closed"
)]
fn standard(selection: Stdio<'_>, index: usize) -> io::Result<Option<OwnedHandle>> {
    match selection {
        Stdio::Closed => Ok(None),
        Stdio::Handle(handle) => duplicate(handle).map(Some),
        Stdio::Null => {
            let file = OpenOptions::new()
                .read(index == 0)
                .write(index != 0)
                .open("NUL")?;
            Ok(Some(file.into()))
        }
        Stdio::Inherit => {
            // SAFETY: the three fixed indices map only to native standard slots.
            let raw = unsafe {
                GetStdHandle([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE][index])
            };
            if raw.is_null() {
                return Ok(None);
            }
            if raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: this GetStdHandle result is borrowed only during duplication.
            duplicate(unsafe { BorrowedHandle::borrow_raw(raw) }).map(Some)
        }
    }
}
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; 16]);
struct Attributes<'a> {
    blocks: Vec<Block>,
    handles: std::marker::PhantomData<&'a [HANDLE]>,
}
impl<'a> Attributes<'a> {
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.blocks.as_mut_ptr().cast()
    }
    #[expect(
        unsafe_code,
        reason = "Native attribute-list APIs initialize one bounded aligned allocation and borrow a stable handle array through the following synchronous CreateProcessW call"
    )]
    fn new(handles: &'a [HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: null buffer performs the documented size query for one attribute.
        let _query =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        if bytes > 128 * 1024 {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let count = bytes.div_ceil(size_of::<Block>());
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        blocks.resize(count, Block([0; 16]));
        // SAFETY: exact native requested size backed by initialized aligned storage.
        if unsafe {
            InitializeProcThreadAttributeList(blocks.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Self {
            blocks,
            handles: std::marker::PhantomData,
        };
        // SAFETY: handles stay stable/live until CreateProcessW returns; the list
        // owns only metadata and never assumes ownership of the handle array.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(attributes)
    }
}
impl Drop for Attributes<'_> {
    #[expect(
        unsafe_code,
        reason = "The successful initialized native attribute list is destroyed once before its allocation and borrowed handle array are released"
    )]
    fn drop(&mut self) {
        // SAFETY: this is the original successfully initialized attribute list.
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}
#[derive(Clone, Copy)]
enum Start<'a> {
    Running,
    Suspended,
    SocketPublication(ActivationHint<'a>),
}
#[derive(Clone, Copy)]
enum ActivationHint<'a> {
    Inherited {
        publisher: Option<&'a Sid>,
    },
    Bootstrap {
        key: &'a OsStr,
        declaration: &'a OsStr,
    },
}
pub(super) struct Created {
    pub(super) process: Process,
    pub(super) thread: OwnedHandle,
}
impl Spawn<'_> {
    /// Create one real process, retaining the original handle. Success means
    /// CreateProcessW admission only; image initialization and service readiness
    /// remain separate observations. Failed creation closes all private copies,
    /// preserving callers' originals and the Win32 error. Input/resource failures
    /// occur before creation. Exported resources are kernel handles, not sockets.
    ///
    /// Private launch copies are briefly inheritable under a shared launch lock.
    /// Callers must exclude unrelated legacy CreateProcess calls using unrestricted
    /// handle inheritance during this synchronous operation. This call itself
    /// always uses an explicit allowlist. No process-global environment or stdio
    /// slot is changed. Detached creation does not wait for or synthesize READY.
    pub fn launch(self, limits: LaunchLimits) -> io::Result<Process> {
        self.create(limits, Start::Running, None)
            .map(|created| created.process)
    }
    /// Launch detached under the verified account without exporting supervisor handles.
    /// The native cleanup owns the loaded profile until this exact process exits.
    pub fn launch_as(
        self,
        profile: AccountProfile,
        limits: LaunchLimits,
    ) -> io::Result<(Process, ProfileCleanup)> {
        self.validate_account_launch()?;
        let cleanup = profile.cleanup()?;
        let process = self
            .create(limits, Start::Running, Some(profile.token()?))?
            .process;
        profile.attach(&process);
        Ok((process, cleanup))
    }

    /// Create the original cross-account process suspended for socket publication.
    /// The original session and target account determine how the child receives
    /// its read-only section. Different sessions use an authenticated grant.
    pub fn suspend_as(
        self,
        profile: AccountProfile,
        section: &mut AccountExportSection<'_>,
        environment_key: &OsStr,
        limits: LaunchLimits,
    ) -> io::Result<(super::SuspendedProcess, ProfileCleanup)> {
        self.validate_account_launch()?;
        let token = profile.token()?;
        let cleanup = profile.cleanup()?;
        let child = self.suspend_with_admission(
            section.admission(token)?,
            environment_key,
            limits,
            Some(token),
        )?;
        profile.attach(child.process());
        Ok((child, cleanup))
    }

    /// Create the one same-account child authorized to import this section.
    /// The original primary thread stays suspended until publication succeeds.
    pub fn suspend_for_activation(
        self,
        section: &mut ExportSection<'_>,
        environment_key: &OsStr,
        limits: LaunchLimits,
    ) -> io::Result<super::SuspendedProcess> {
        if !self.exported_handles.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket activation reserves the launch handle export",
            ));
        }
        self.suspend_with_admission(section.admission()?, environment_key, limits, None)
    }

    fn suspend_with_admission(
        self,
        admission: Admission<'_>,
        environment_key: &OsStr,
        limits: LaunchLimits,
        token: Option<&PrimaryToken>,
    ) -> io::Result<super::SuspendedProcess> {
        let created = match admission.delivery() {
            Delivery::Inherited { handle, publisher } => {
                let export = [ExportedHandle {
                    handle,
                    environment_key,
                }];
                Spawn {
                    exported_handles: &export,
                    ..self
                }
                .create(
                    limits,
                    Start::SocketPublication(ActivationHint::Inherited { publisher }),
                    token,
                )?
            }
            Delivery::Bootstrap(declaration) => self.create(
                limits,
                Start::SocketPublication(ActivationHint::Bootstrap {
                    key: environment_key,
                    declaration,
                }),
                token,
            )?,
        };
        let child = super::SuspendedProcess::for_activation(created);
        admission.bind(&child);
        Ok(child)
    }

    fn validate_account_launch(&self) -> io::Result<()> {
        if !self.exported_handles.is_empty()
            || !self.stdio.iter().all(|slot| matches!(slot, Stdio::Closed))
            || !matches!(self.console, Console::Detached)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "account launch requires a detached process without inherited handles",
            ));
        }
        Ok(())
    }
    /// Create one original process with its primary thread suspended. No user
    /// image initialization or readiness is implied. The caller must explicitly
    /// resume or terminate/drain it; dropping owners never resumes or kills it.
    /// Source/stdio/allowlist and capacity rules are identical to `launch`.
    pub fn suspend(self, limits: LaunchLimits) -> io::Result<super::suspended::SuspendedProcess> {
        self.create(limits, Start::Suspended, None)
            .map(super::suspended::SuspendedProcess::from_created)
    }
    #[expect(
        unsafe_code,
        reason = "Windows creation APIs borrow validated UTF-16 inputs, an optional live token and an explicit private allowlist; successful handles fill reserved ownership"
    )]
    fn create(
        self,
        limits: LaunchLimits,
        start: Start<'_>,
        token: Option<&PrimaryToken>,
    ) -> io::Result<Created> {
        if !self.executable.is_absolute()
            || !self.directory.is_absolute()
            || limits.command_units == 0
            || limits.command_units > 32767
            || limits.environment_units < 2
            || limits.environment_units > i32::MAX as usize
            || self.arguments.len() > limits.arguments
            || self
                .exported_handles
                .len()
                .checked_add(3)
                .is_none_or(|n| n > limits.handles)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native process launch geometry",
            ));
        }
        let executable = absolute_wide_path(self.executable)?;
        let directory = absolute_wide_path(self.directory)?;
        let process_security = match token {
            Some(token) if matches!(start, Start::SocketPublication(_)) => {
                // WSADuplicateSocket targets a PID; a provider may open it for handle
                // duplication. The CreateProcessAsUser default may admit only the child account.
                Some(PrivateSecurityDescriptor::process_with_socket_publisher(
                    token.user(),
                )?)
            }
            _ => None,
        };
        let mut process_attributes = process_security
            .as_ref()
            .map(PrivateSecurityDescriptor::attributes);
        let mut arguments = Vec::new();
        arguments
            .try_reserve_exact(self.arguments.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut remaining = limits.command_units;
        for argument in self.arguments {
            let value = environment::wide(argument, remaining)?;
            remaining = remaining.saturating_sub(value.len());
            arguments.push(value);
        }
        let argv0 = environment::wide(self.argv0, limits.command_units)?;
        let mut command =
            crate::windows_command_line::encode(&argv0, &arguments, limits.command_units)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(self.exported_handles.len() + 3)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        // Reserve the sole process-object allocation before native admission.
        // No allocation can strand a newly created suspended process here.
        let process_storage = Arc::<ProcessObject>::new_uninit();
        let mut standard_handles = [ptr::null_mut(); 3];
        for (index, selection) in self.stdio.into_iter().enumerate() {
            if let Some(handle) = standard(selection, index)? {
                standard_handles[index] = handle.as_raw_handle();
                owned.push(handle);
            }
        }
        let mut exports = Vec::new();
        let (bootstrap, publisher) = match start {
            Start::SocketPublication(ActivationHint::Bootstrap { key, declaration }) => {
                (Some((key, declaration)), None)
            }
            Start::SocketPublication(ActivationHint::Inherited { publisher }) => (None, publisher),
            _ => (None, None),
        };
        exports
            .try_reserve_exact(self.exported_handles.len() + usize::from(bootstrap.is_some()))
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for export in self.exported_handles {
            let handle = duplicate(export.handle)?;
            let raw = handle.as_raw_handle() as usize;
            let value = match publisher {
                Some(publisher) => format!("{ACCOUNT_HANDLE_PREFIX}{raw:x}:{publisher}"),
                None => format!("{raw:x}"),
            };
            exports.push((export.environment_key.to_os_string(), value.into()));
            owned.push(handle);
        }
        if let Some((key, declaration)) = bootstrap {
            exports.push((key.to_os_string(), declaration.to_os_string()));
        }
        let environment = environment::encode(
            self.environment,
            &exports,
            limits.environment_units,
            limits.environment_entries,
        )?;
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(owned.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        handles.extend(owned.iter().map(AsRawHandle::as_raw_handle));
        let exclusive = (!handles.is_empty()).then(|| {
            INHERITANCE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        let result = (|| {
            for handle in &handles {
                // SAFETY: only private live duplicates are marked inheritable.
                if unsafe {
                    SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut attributes = if handles.is_empty() {
                None
            } else {
                Some(Attributes::new(&handles)?)
            };
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = if attributes.is_some() {
                size_of::<STARTUPINFOEXW>()
            } else {
                size_of::<STARTUPINFOW>()
            } as u32;
            if token.is_none() {
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            }
            [
                startup.StartupInfo.hStdInput,
                startup.StartupInfo.hStdOutput,
                startup.StartupInfo.hStdError,
            ] = standard_handles;
            startup.lpAttributeList = attributes
                .as_mut()
                .map_or(ptr::null_mut(), Attributes::pointer);
            let flags = CREATE_UNICODE_ENVIRONMENT
                | match start {
                    Start::Running => 0,
                    Start::Suspended | Start::SocketPublication(_) => CREATE_SUSPENDED,
                }
                | if attributes.is_some() {
                    EXTENDED_STARTUPINFO_PRESENT
                } else {
                    0
                }
                | match self.console {
                    Console::Inherit => 0,
                    Console::NewProcessGroup => CREATE_NEW_PROCESS_GROUP,
                    Console::Detached => DETACHED_PROCESS,
                };
            let mut output = PROCESS_INFORMATION::default();
            // SAFETY: all strings are terminated; the command buffer is mutable;
            // metadata, handle array and private resources stay live for this call.
            let status = unsafe {
                if let Some(token) = token {
                    CreateProcessAsUserW(
                        token.raw(),
                        executable.as_ptr(),
                        command.as_mut_ptr(),
                        process_attributes
                            .as_mut()
                            .map_or(ptr::null(), |attributes| {
                                attributes.as_mut_ptr().cast_const().cast()
                            }),
                        ptr::null(),
                        i32::from(!handles.is_empty()),
                        flags,
                        environment.as_ptr().cast(),
                        directory.as_ptr(),
                        &startup.StartupInfo,
                        &mut output,
                    )
                } else {
                    CreateProcessW(
                        executable.as_ptr(),
                        command.as_mut_ptr(),
                        ptr::null(),
                        ptr::null(),
                        i32::from(!handles.is_empty()),
                        flags,
                        environment.as_ptr().cast(),
                        directory.as_ptr(),
                        &startup.StartupInfo,
                        &mut output,
                    )
                }
            };
            if status == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful CreateProcessW transfers two independent handles.
            let process = unsafe { OwnedHandle::from_raw_handle(output.hProcess) };
            // SAFETY: this is the distinct primary-thread handle, not process ownership.
            let thread = unsafe { OwnedHandle::from_raw_handle(output.hThread) };
            // SAFETY: this uninitialized Arc is uniquely owned, never lent or
            // cloned. Native success supplies every field before assume_init.
            let process = unsafe {
                Arc::as_ptr(&process_storage)
                    .cast_mut()
                    .write(std::mem::MaybeUninit::new(ProcessObject {
                        handle: process,
                        id: output.dwProcessId,
                    }));
                Process(process_storage.assume_init())
            };
            Ok(Created { process, thread })
        })();
        // End the inheritance window before releasing our shared launch lock.
        drop(owned);
        drop(exclusive);
        result
    }
}
