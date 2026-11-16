//! Fresh standalone child processes exercise real Windows stderr ownership.
#[cfg(windows)]
mod windows {
    use gnunet_native::{
        paths,
        stdio::{
            ConsoleDetachFailure, DetachedStderr, PreparedStderr, ProcessStderr,
            Stdio as NativeStdio, detach_console,
        },
    };
    use std::{
        fs,
        io::{self, Read, Write},
        os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
        System::{
            Console::{
                GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
            },
            Threading::GetCurrentProcess,
        },
    };
    #[expect(
        unsafe_code,
        reason = "The fixture binds UCRT's documented _setmode ABI, absent from libc's Rust bindings; calls occur only with a known live child descriptor under stream exclusion"
    )]
    unsafe extern "C" {
        fn _setmode(fd: std::ffi::c_int, mode: std::ffi::c_int) -> std::ffi::c_int;
    }

    fn check(condition: bool, message: &'static str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    #[expect(
        unsafe_code,
        reason = "This standalone child main is single-threaded, has not used buffered standard streams, and exclusively owns all following standard-handle changes"
    )]
    fn claim() -> io::Result<ProcessStderr> {
        // SAFETY: called only by the fresh child, with every stream user quiescent.
        unsafe { ProcessStderr::claim() }
    }
    fn install(directory: &Path, name: &str) -> io::Result<()> {
        let mut capability = claim()?;
        check(claim().is_err(), "a second stderr capability was granted")?;
        let file = paths::create_private_file(&directory.join(name))?;
        capability.install(&file).map_err(io::Error::other)?;
        // Drop both caller-owned objects before writing through either interface.
        drop(file);
        drop(capability);
        Ok(())
    }
    #[expect(
        unsafe_code,
        reason = "The child just installed a valid fd2; GetStdHandle is borrowed and _get_osfhandle queries only that known-live descriptor"
    )]
    fn check_independent_owners() -> io::Result<()> {
        // SAFETY: no descriptor mutation occurs concurrently in this child.
        let (win32, crt) = unsafe { (GetStdHandle(STD_ERROR_HANDLE), libc::get_osfhandle(2)) };
        check(
            win32 as isize != crt,
            "Win32 stderr aliases CRT-owned handle",
        )
    }
    fn write_markers(prefix: &str) -> io::Result<()> {
        check_independent_owners()?;
        io::stderr().write_all(format!("{prefix}:Rust\n").as_bytes())?;
        let bytes = format!("{prefix}:CRT\n");
        #[expect(
            unsafe_code,
            reason = "Known-live installed fd2 receives one bounded byte buffer; the child excludes all mutation and the fixture checks the exact write count"
        )]
        // SAFETY: buffer is live for the synchronous write and its length fits u32.
        let count = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len() as u32) };
        check(
            count == bytes.len() as i32,
            "CRT stderr write failed or was short",
        )
    }
    fn set_standard(which: u32, handle: HANDLE) -> io::Result<()> {
        #[expect(
            unsafe_code,
            reason = "Child-only setup/cleanup borrows a known-live saved handle, or stores NULL after its last stream user"
        )]
        // SAFETY: the standard selector is valid and all standard users are quiescent.
        if unsafe { SetStdHandle(which, handle) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn duplicate_standard(which: u32) -> io::Result<OwnedHandle> {
        let mut result = std::ptr::null_mut();
        #[expect(
            unsafe_code,
            reason = "The parent supplied live pipe standard handles; DuplicateHandle creates one independent noninheritable child-owned copy"
        )]
        // SAFETY: no standard-handle mutation occurs until both copies are owned.
        let status = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                GetStdHandle(which),
                process,
                &mut result,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if status == 0 {
            return Err(io::Error::last_os_error());
        }
        #[expect(
            unsafe_code,
            reason = "Exactly one fresh DuplicateHandle result is transferred into unique ownership"
        )]
        // SAFETY: no other owner exists for this successful duplicate.
        Ok(unsafe { OwnedHandle::from_raw_handle(result) })
    }
    fn close_crt(slot: i32) -> io::Result<()> {
        #[expect(
            unsafe_code,
            reason = "The test closes only fd2 installed above or fd0/fd1 first initialized by a checked dup2 from valid fd2"
        )]
        // SAFETY: slot has known live CRT ownership, and the test closes it once.
        let status = unsafe { libc::close(slot) };
        check(status == 0, "closing a known-live CRT slot failed")
    }
    fn child(case: &str, directory: &Path) -> io::Result<()> {
        if case.starts_with("stdout-") {
            let original = io::stdout().as_raw_handle();
            let mut output = gnunet_native::stdio::Output::stdout()?;
            let replacement = fs::File::create(directory.join("replacement"))?;
            // SetStdHandle does not close the original process/CRT-owned route.
            // This fresh child has no competing stdout writer or table mutation.
            set_standard(STD_OUTPUT_HANDLE, replacement.as_raw_handle())?;
            let written = output
                .write_all("original stdout λ\n".as_bytes())
                .and_then(|()| output.flush());
            let restored = set_standard(STD_OUTPUT_HANDLE, original);
            written?;
            restored?;
            return check(
                replacement.metadata()?.len() == 0,
                "stdout writer followed a replacement route",
            );
        }
        if case.starts_with("detach-") {
            if case == "detach-snapshot" {
                return snapshot_child(directory);
            }
            return detach_child(case);
        }
        install(directory, "first.log")?;
        write_markers("first")?;
        let mut saved = None;
        if case == "closed-all" {
            let input = duplicate_standard(STD_INPUT_HANDLE)?;
            let output = duplicate_standard(STD_OUTPUT_HANDLE)?;
            for slot in [0, 1] {
                #[expect(
                    unsafe_code,
                    reason = "The child initializes each possibly closed CRT slot from known-live fd2 before closing it; original Win32 input/output were duplicated beforehand"
                )]
                // SAFETY: fd2 is live and slot is a valid standard descriptor number.
                let initialized = unsafe { libc::dup2(2, slot) };
                check(initialized == 0, "initializing CRT slot failed")?;
                close_crt(slot)?;
            }
            set_standard(STD_INPUT_HANDLE, input.as_raw_handle())?;
            set_standard(STD_OUTPUT_HANDLE, output.as_raw_handle())?;
            saved = Some((input, output));
        }
        if matches!(case, "closed-stderr" | "closed-all") {
            #[expect(
                unsafe_code,
                reason = "This borrowed standard handle belongs to the native independent process owner, not CRT fd2"
            )]
            // SAFETY: it remains live across closing the separate CRT-owned handle.
            let win32 = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
            close_crt(2)?;
            set_standard(STD_ERROR_HANDLE, win32)?;
        }
        if case != "normal" {
            install(directory, "second.log")?;
            write_markers("second")?;
            install(directory, "third.log")?;
            write_markers("third")?;
        }
        // Closed CRT input/output slots must not erase independently live native
        // stdin/stdout. Rust accesses the native table, not CRT fd0/fd1.
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input)?;
        check(
            input == b"input\n",
            "native stdin changed during stderr preparation",
        )?;
        io::stdout().write_all(b"stdout\n")?;
        if saved.is_some() {
            set_standard(STD_INPUT_HANDLE, std::ptr::null_mut())?;
            set_standard(STD_OUTPUT_HANDLE, std::ptr::null_mut())?;
        }
        drop(saved);
        Ok(())
    }
    #[expect(
        unsafe_code,
        reason = "Fresh standalone child exclusively owns streams/console before any handler or task; native slot queries are borrowed and bounded CRT probes use only installed live slots"
    )]
    fn detach_child(case: &str) -> io::Result<()> {
        if case == "detach-alias" {
            // SAFETY: original routes stay borrowed/live. The documented alias
            // preflight rejects before any installation or handle close occurs.
            let (output, error) = unsafe {
                (
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    GetStdHandle(STD_ERROR_HANDLE),
                )
            };
            set_standard(STD_OUTPUT_HANDLE, error)?;
            // SAFETY: the declared alias preflight guarantees no installation or close.
            let result = unsafe { detach_console() };
            set_standard(STD_OUTPUT_HANDLE, output)?;
            check(
                matches!(result, Err(ConsoleDetachFailure::Prepare(error)) if error.kind() == io::ErrorKind::InvalidInput),
                "aliased standard routes were changed or silently accepted",
            )?;
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input)?;
            check(input == b"input\n", "alias refusal changed stdin")?;
            io::stdout().write_all(b"stdout\n")?;
            return Ok(());
        }
        // SAFETY: the parent supplies a live pipe/NUL fd2, no buffering or other
        // stream user exists, and this fixture explicitly controls its mode.
        let mode = unsafe { _setmode(2, libc::O_BINARY) };
        check(mode >= 0, "setting the fixture's CRT stderr mode failed")?;
        // SAFETY: no stream has been used/buffered or exposed to another owner.
        let route = unsafe { detach_console() }.map_err(io::Error::other)?;
        check(
            route
                == if case == "detach-null" {
                    DetachedStderr::Null
                } else {
                    DetachedStderr::Preserved
                },
            "detached stderr route differs from its native kind",
        )?;
        if case == "detach-repeat" {
            // SAFETY: the same fresh process still excludes users/mutation and
            // holds no cached standard handle; repeated detachment is explicit.
            let repeated = unsafe { detach_console() }.map_err(io::Error::other)?;
            check(repeated == route, "repeated detach changed stderr")?;
        }
        // SAFETY: fd2 is the preserved live pipe or installed NUL; observing its
        // old mode via _setmode changes neither ownership nor destination.
        let mode = unsafe { _setmode(2, libc::O_BINARY) };
        check(
            mode == libc::O_BINARY,
            "detachment changed the selected CRT stderr mode",
        )?;
        let mut byte = [0];
        check(
            io::stdin().read(&mut byte)? == 0,
            "native detached stdin is not NUL",
        )?;
        // SAFETY: fd0 was successfully installed from a live NUL source.
        let count = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
        check(count == 0, "CRT detached stdin is not NUL")?;
        io::stdout().write_all(b"native detached stdout\n")?;
        let bytes = b"CRT detached stdout\n";
        // SAFETY: installed live fd1 and complete bounded synchronous buffer.
        let count = unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len() as u32) };
        check(count == bytes.len() as i32, "CRT detached stdout failed")?;
        io::stderr().write_all(b"detach:Rust\n")?;
        let bytes = b"detach:CRT\n";
        // SAFETY: fd2 retains its original live pipe or a successfully installed NUL.
        let count = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len() as u32) };
        check(count == bytes.len() as i32, "CRT detached stderr failed")
    }
    fn snapshot_child(directory: &Path) -> io::Result<()> {
        let file = fs::File::create(directory.join("snapshot.log"))?;
        let snapshot = PreparedStderr::new(NativeStdio::Handle(file.as_handle()))?;
        drop(file);
        let NativeStdio::Handle(handle) = snapshot.stdio() else {
            return Err(io::Error::other(
                "file stderr did not retain an original handle",
            ));
        };
        let mut writer = fs::File::from(handle.try_clone_to_owned()?);
        writer.write_all(b"original pinned stderr\n")?;
        drop(writer);
        let null = fs::OpenOptions::new().read(true).write(true).open("NUL")?;
        check(
            matches!(
                PreparedStderr::new(NativeStdio::Handle(null.as_handle()))?.stdio(),
                NativeStdio::Null
            ),
            "character stderr was left unusable in a detached child",
        )?;
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input)?;
        check(input == b"input\n", "stderr preparation changed stdin")?;
        io::stdout().write_all(b"snapshot\n")
    }
    fn run_directory() -> io::Result<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/native-stdio");
        fs::create_dir_all(&root)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = root.join(format!("{}-{stamp}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(path)
    }
    pub(super) fn main() -> io::Result<()> {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--stderr-child")) {
            let case = arguments
                .next()
                .and_then(|s| s.into_string().ok())
                .ok_or(io::ErrorKind::InvalidInput)?;
            let directory = arguments.next().ok_or(io::ErrorKind::InvalidInput)?;
            return child(&case, Path::new(&directory));
        }
        let directory = run_directory()?;
        for case in ["stdout-pipe", "stdout-file"] {
            let path = directory.join(case);
            fs::create_dir(&path)?;
            let destination = path.join("original");
            let output = Command::new(std::env::current_exe()?)
                .arg("--stderr-child")
                .arg(case)
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(if case == "stdout-pipe" {
                    Stdio::piped()
                } else {
                    fs::File::create(&destination)?.into()
                })
                .stderr(Stdio::piped())
                .output()?;
            check(
                output.status.success(),
                "original stdout owner child failed",
            )?;
            let bytes = if case == "stdout-pipe" {
                output.stdout
            } else {
                fs::read(&destination)?
            };
            check(
                bytes == "original stdout λ\n".as_bytes(),
                "stdout bytes or pinned identity changed",
            )?;
        }
        for case in ["normal", "repeat", "closed-stderr", "closed-all"] {
            let path = directory.join(case);
            fs::create_dir(&path)?;
            let mut child = Command::new(std::env::current_exe()?)
                .arg("--stderr-child")
                .arg(case)
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut input = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("missing child stdin pipe"))?;
            input.write_all(b"input\n")?;
            drop(input);
            let output = child.wait_with_output()?;
            check(
                output.status.success(),
                "stderr ownership child failed; inspect target/native-stdio logs",
            )?;
            check(
                output.stderr.is_empty(),
                "redirected child wrote to original stderr pipe",
            )?;
            check(
                output.stdout == b"stdout\n",
                "native stdout changed during stderr preparation",
            )?;
            for name in if case == "normal" {
                &["first"][..]
            } else {
                &["first", "second", "third"][..]
            } {
                let bytes = fs::read(path.join(format!("{name}.log")))?;
                check(
                    bytes == format!("{name}:Rust\n{name}:CRT\n").as_bytes(),
                    "stderr destination bytes or ownership differ",
                )?;
            }
        }
        let input = directory.join("detach-input");
        fs::write(&input, b"input\n")?;
        for case in [
            "detach-pipe",
            "detach-repeat",
            "detach-null",
            "detach-alias",
            "detach-snapshot",
        ] {
            let error = if case == "detach-null" {
                Stdio::null()
            } else {
                Stdio::piped()
            };
            let output = Command::new(std::env::current_exe()?)
                .arg("--stderr-child")
                .arg(case)
                .arg(&directory)
                .stdin(Stdio::from(fs::File::open(&input)?))
                .stdout(Stdio::piped())
                .stderr(error)
                .output()?;
            check(
                output.status.success(),
                "native console-detach child failed",
            )?;
            check(
                output.stdout
                    == if case == "detach-alias" {
                        &b"stdout\n"[..]
                    } else if case == "detach-snapshot" {
                        &b"snapshot\n"[..]
                    } else {
                        &[][..]
                    },
                "detachment did not select the expected native/CRT stdout",
            )?;
            check(
                output.stderr
                    == if case == "detach-null"
                        || case == "detach-alias"
                        || case == "detach-snapshot"
                    {
                        &[][..]
                    } else {
                        &b"detach:Rust\ndetach:CRT\n"[..]
                    },
                "detachment changed file/pipe stderr",
            )?;
            if case == "detach-snapshot" {
                check(
                    fs::read(directory.join("snapshot.log"))? == b"original pinned stderr\n",
                    "stderr snapshot reopened or lost its original file",
                )?;
            }
        }
        fs::remove_dir_all(directory)
    }
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    windows::main()
}
#[cfg(not(windows))]
fn main() {}
