//! Native Windows logging policy with isolated locale selection and lossless inputs.
#[cfg(windows)]
mod windows {
    use gnunet_native::os_bytes;
    use gnunet_program_host::policy::{CallSite, Level, Policy};
    use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, process::Command};
    #[expect(
        unsafe_code,
        reason = "UCRT locale.h declares this selector; only the standalone single-thread child calls it"
    )]
    unsafe extern "C" {
        fn _wsetlocale(category: i32, name: *const u16) -> *const u16;
    }
    fn select(name: &str) -> io::Result<()> {
        let value: Vec<_> = name.encode_utf16().chain([0]).collect();
        #[expect(
            unsafe_code,
            reason = "Fresh child exclusively owns all locale changes; the valid category and terminated input stay live through selection"
        )]
        // SAFETY: no native locale reader or callback runs concurrently here.
        let selected = unsafe { _wsetlocale(libc::LC_ALL, value.as_ptr()) };
        if selected.is_null() {
            return Err(io::Error::other(format!(
                "native locale unavailable: {name}"
            )));
        }
        Ok(())
    }
    fn enabled(policy: &mut Policy, component: &[u8]) -> io::Result<bool> {
        policy.enabled(
            Level::DEBUG,
            component,
            CallSite {
                component: None,
                file: b"unit.rs",
                function: b"probe",
                line: 1,
            },
        )
    }
    fn policy(pattern: &[u8]) -> io::Result<Policy> {
        let mut rule = pattern.to_vec();
        rule.extend_from_slice(b";;;;DEBUG/;;;;NONE");
        let mut policy = Policy::default();
        policy.setup(None, Some(&rule), None)?;
        if policy.definitions() != 2 {
            return Err(io::Error::other("valid BRE policy rejected"));
        }
        Ok(policy)
    }
    fn require(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn child(name: &str) -> io::Result<()> {
        select(name)?;
        let mut captures = policy(br"^\(a*\)a*\1$")?;
        require(
            enabled(&mut captures, b"a")?,
            "valid empty capture history was discarded",
        )?;
        require(
            !enabled(&mut captures, b"aab")?,
            "non-matching backreference was accepted",
        )?;
        let mut unicode = policy("^😀\\{2\\}$".as_bytes())?;
        require(
            enabled(&mut unicode, "😀😀".as_bytes())?,
            "supplementary characters were split into surrogate halves",
        )?;
        require(
            !enabled(&mut unicode, "😀".as_bytes())?,
            "Unicode repetition count changed",
        )?;
        let raw = OsString::from_wide(&[0xd800]);
        let pattern = OsString::from_wide(&[94, 0xd800, 36]);
        let mut raw_policy = policy(&os_bytes::encode(&pattern))?;
        require(
            enabled(&mut raw_policy, &os_bytes::encode(&raw))?,
            "isolated native unit was not preserved",
        )?;
        if name != "C" {
            let mut letters = policy(br"^[[:alpha:]]$")?;
            let mut equivalent = policy(br"^[[=a=]]$")?;
            let mut range = policy(br"^[a-z]$")?;
            select("C")?;
            require(
                enabled(&mut letters, "ä".as_bytes())?,
                "retained native alphabet classification changed",
            )?;
            require(
                enabled(&mut equivalent, "ä".as_bytes())?,
                "primary collation equivalence was lost",
            )?;
            require(
                enabled(&mut range, "ä".as_bytes())?,
                "retained locale range changed",
            )?;
        }
        let mut limited = policy(br"^a*b$")?;
        require(
            enabled(&mut limited, &vec![b'a'; 65537]).is_err(),
            "resource refusal became a negative match",
        )?;
        let mut malformed = Policy::default();
        malformed.setup(None, Some(b";;;;INFO/[;;;;DEBUG/;;;;NONE"), None)?;
        require(
            malformed.definitions() == 1,
            "invalid pattern discarded preceding valid rules",
        )?;
        Ok(())
    }
    pub(super) fn run() -> io::Result<()> {
        if let Some(name) = std::env::args().nth(1) {
            return child(&name);
        }
        for name in ["C", "de-DE", "German_Germany.1252", "en-150"] {
            let output = Command::new(std::env::current_exe()?).arg(name).output()?;
            require(
                output.status.success(),
                "native Windows logging child failed",
            )
            .map_err(|error| {
                io::Error::other(format!(
                    "{name}: {error}: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            })?;
        }
        Ok(())
    }
}
#[cfg(windows)]
fn main() -> std::io::Result<()> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {}
