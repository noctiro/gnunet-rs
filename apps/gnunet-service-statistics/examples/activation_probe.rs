//! Single-threaded actual-process fixture for inherited fd ownership and private bind modes.
#[cfg(unix)]
use gnunet_service_runtime::activation;
#[cfg(unix)]
mod fixture {
    use crate::activation::{self, ActivatedSocket, Activation};
    use std::{
        io::{self, Read, Write},
        os::{
            fd::{AsRawFd, BorrowedFd, RawFd},
            unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        },
        path::PathBuf,
        process::ExitCode,
        time::{Duration, Instant},
    };

    pub(super) fn run_main() -> ExitCode {
        let mode = std::env::var("ACTIVATION_PROBE_MODE").unwrap_or_else(|_| "inspect".into());
        let tracked = std::env::var("ACTIVATION_PROBE_TRACK_FDS")
            .unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse::<RawFd>().ok())
            .collect::<Vec<_>>();
        let path = std::env::var_os("ACTIVATION_PROBE_PATH").map(PathBuf::from);
        let report_path = std::env::var_os("ACTIVATION_PROBE_REPORT_PATH").map(PathBuf::from);
        let low_stdio = std::env::var("LISTEN_FDNAMES")
            .unwrap_or_default()
            .split(':')
            .filter_map(|s| s.parse::<RawFd>().ok())
            .filter(|fd| (0..3).contains(fd))
            .collect::<Vec<_>>();
        let initial_mask = fixture_native_setup();
        #[expect(
            unsafe_code,
            reason = "This freshly execed single-threaded fixture has only foreign inherited descriptors, with no runtime or files opened before capture"
        )]
        // SAFETY: this is the first ownership capture, before stdio/file/runtime use;
        // the Python parent exclusively transfers the named pass_fds descriptors.
        let result = unsafe { activation::capture() };
        let result = run(
            mode,
            tracked,
            path,
            initial_mask,
            result,
            low_stdio,
            report_path,
        );
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                if writeln!(io::stderr().lock(), "activation probe: {error}").is_err() {
                    return ExitCode::FAILURE;
                }
                ExitCode::FAILURE
            }
        }
    }

    #[expect(
        unsafe_code,
        reason = "The isolated single-threaded subprocess fixture only toggles a known foreign fd's flags or establishes its test umask before ownership capture"
    )]
    fn fixture_native_setup() -> u32 {
        if let Ok(fd) = std::env::var("ACTIVATION_PROBE_CLOEXEC_FD")
            .unwrap_or_default()
            .parse::<RawFd>()
        {
            // SAFETY: integer-only fcntl accepts any fd and reports invalid values;
            // no Rust owner exists for the descriptor in this fresh test process.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 {
                // SAFETY: F_SETFD takes only these integers on the same live foreign fd.
                unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            }
        }
        let mask = std::env::var("ACTIVATION_PROBE_UMASK")
            .ok()
            .and_then(|s| u32::from_str_radix(&s, 8).ok())
            .unwrap_or(0o022);
        // SAFETY: umask takes a numeric mask without memory preconditions; no other
        // threads or file creators exist in this subprocess.
        unsafe { libc::umask(mask as libc::mode_t) };
        mask
    }
    #[expect(
        unsafe_code,
        reason = "The test reads fd validity using pointer-free F_GETFD without constructing additional ownership"
    )]
    fn flags(fd: RawFd) -> i32 {
        // SAFETY: F_GETFD has no pointer argument and cannot close or take ownership.
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }
    #[expect(
        unsafe_code,
        reason = "This isolated single-threaded subprocess observes and immediately restores its process umask without opening files between calls"
    )]
    fn mask() -> u32 {
        // SAFETY: no memory arguments or concurrent environment/file users.
        let previous = unsafe { libc::umask(0) };
        // SAFETY: immediately restore the value just returned; no threads or file opens intervened.
        unsafe { libc::umask(previous) };
        previous as u32
    }
    #[expect(
        unsafe_code,
        reason = "The single-threaded fixture borrows only a just-checked live standard descriptor to clone it safely for null-device metadata comparison, without owning or closing the standard slot"
    )]
    fn is_null_device(fd: RawFd) -> io::Result<bool> {
        if flags(fd) < 0 {
            return Ok(false);
        }
        // SAFETY: F_GETFD just established this still-live stdio slot; the
        // fixture has no concurrent close/reuse or standard-stream owners.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let copy = std::fs::File::from(borrowed.try_clone_to_owned()?);
        let actual = copy.metadata()?;
        let expected = std::fs::metadata("/dev/null")?;
        Ok(actual.file_type().is_char_device()
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && actual.rdev() == expected.rdev())
    }
    fn run(
        mode: String,
        tracked: Vec<RawFd>,
        path: Option<PathBuf>,
        initial_mask: u32,
        result: io::Result<Activation>,
        low_stdio: Vec<RawFd>,
        report_path: Option<PathBuf>,
    ) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        let native_layout = [
            activation::DARWIN_SOCKET_OPTIONS_OFFSET,
            activation::DARWIN_SOCKET_INFO_BUFFER_BYTES,
        ];
        #[cfg(not(target_os = "macos"))]
        let native_layout = [0_usize; 2];
        let mut socket_fds = Vec::new();
        let accepted = result.is_ok();
        let error_kind = result
            .as_ref()
            .err()
            .map(|e| format!("{:?}", e.kind()))
            .unwrap_or_default();
        let activation = result.unwrap_or_default();
        for socket in &activation.sockets {
            socket_fds.push(match socket {
                ActivatedSocket::Unix(s) => s.as_raw_fd(),
                ActivatedSocket::Tcp(s) => s.as_raw_fd(),
            });
        }
        let count = activation.sockets.len();
        let live_flags: Vec<_> = socket_fds.iter().map(|fd| flags(*fd)).collect();
        let consumed_count_hint = std::env::var_os("LISTEN_FDS").is_none();
        let duplicate_capture_rejected = if mode == "duplicate-capture" {
            #[expect(
                unsafe_code,
                reason = "The second fixture call tests the one-shot guard, which rejects before any raw ownership or environment operation"
            )]
            // SAFETY: capture's documented repeat guard touches no foreign fds.
            let again = unsafe { activation::capture() };
            again.is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists)
        } else {
            true
        };
        if mode == "serve" {
            writeln!(io::stdout().lock(), "READY {count}")?;
            for socket in &activation.sockets {
                serve_one(socket)?;
            }
        }
        let mut permissions = 0;
        let mut bind_error = false;
        if mode == "private-bind" {
            let path = path.ok_or_else(|| io::Error::other("missing private bind fixture path"))?;
            let listener = activation::bind_private(&path)?;
            permissions = std::fs::symlink_metadata(&path)?.permissions().mode() & 0o777;
            bind_error = activation::bind_private(&path).is_err();
            drop(listener);
            std::fs::remove_file(path)?;
        }
        drop(activation);
        // No operation that creates descriptors may intervene before these checks.
        let original_open: Vec<_> = tracked.iter().map(|fd| flags(*fd) >= 0).collect();
        let owned_closed = socket_fds.iter().all(|fd| flags(*fd) < 0);
        let stdio_restored = low_stdio
            .iter()
            .map(|fd| is_null_device(*fd))
            .collect::<io::Result<Vec<_>>>()?;
        let row = format!(
            "{{\"accepted\":{accepted},\"error_kind\":\"{error_kind}\",\"listeners\":{count},\"listener_fds\":{socket_fds:?},\"owned_closed\":{owned_closed},\"original_fds_open\":{original_open:?},\"stdio_restored\":{stdio_restored:?},\"live_flags\":{live_flags:?},\"count_hint_removed\":{consumed_count_hint},\"duplicate_capture_rejected\":{duplicate_capture_rejected},\"private_mode\":{permissions},\"bind_failure_observed\":{bind_error},\"darwin_socket_layout\":{native_layout:?},\"mask_restored\":{}}}",
            mask() == initial_mask
        );
        if let Some(path) = report_path {
            // Open after all original listener-close observations, so a fresh
            // report fd cannot be mistaken for an unclosed owned listener.
            let mut file = std::fs::File::create(path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            writeln!(file, "{row}")
        } else {
            writeln!(io::stdout().lock(), "{row}")
        }
    }
    fn serve_one(socket: &ActivatedSocket) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result: io::Result<Box<dyn Channel>> = match socket {
                ActivatedSocket::Unix(listener) => listener.accept().and_then(|(s, _)| {
                    s.set_read_timeout(Some(Duration::from_secs(2)))?;
                    Ok(Box::new(s) as Box<dyn Channel>)
                }),
                ActivatedSocket::Tcp(listener) => listener.accept().and_then(|(s, _)| {
                    s.set_read_timeout(Some(Duration::from_secs(2)))?;
                    Ok(Box::new(s) as Box<dyn Channel>)
                }),
            };
            match result {
                Ok(mut stream) => {
                    let mut input = [0];
                    stream.read_exact(&mut input)?;
                    stream.write_all(b"A")?;
                    return Ok(());
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(error),
            }
        }
    }
    trait Channel: Read + Write {}
    impl Channel for std::os::unix::net::UnixStream {}
    impl Channel for std::net::TcpStream {}
}
#[cfg(unix)]
fn main() -> std::process::ExitCode {
    fixture::run_main()
}
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
