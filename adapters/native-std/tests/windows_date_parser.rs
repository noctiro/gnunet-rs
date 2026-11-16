//! Isolated native locale/date scenarios; parent setup never changes its locale or TZ.
#[cfg(windows)]
mod windows {
    use gnunet_native::{
        calendar::{AutomationDateError, Calendar, DateParser, Zone},
        locale::LocaleSnapshot,
    };
    use std::{ffi::OsStr, io, process::Command};

    #[expect(
        unsafe_code,
        reason = "UCRT locale.h's wide locale selector is used only in a fresh single-threaded test child"
    )]
    unsafe extern "C" {
        fn _wsetlocale(category: i32, locale: *const u16) -> *const u16;
    }
    fn check(condition: bool, detail: impl Into<String>) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(detail.into()))
        }
    }
    fn select(name: &str) -> io::Result<()> {
        let wide: Vec<_> = name.encode_utf16().chain([0]).collect();
        #[expect(
            unsafe_code,
            reason = "Only the fresh child calls this with valid LC_TIME and a live terminated locale name, with no other locale user or thread"
        )]
        // SAFETY: no pointer escapes and all prior parser snapshots own their data.
        let selected = unsafe { _wsetlocale(libc::LC_TIME, wide.as_ptr()) };
        check(
            !selected.is_null(),
            format!("cannot select native LC_TIME {name}"),
        )
    }
    fn capture() -> io::Result<DateParser> {
        #[expect(
            unsafe_code,
            reason = "Single-threaded child excludes all locale mutation throughout both native observations"
        )]
        // SAFETY: selection is completed before capture; snapshots are independently owned.
        unsafe {
            DateParser::capture_current_thread()
        }
    }
    fn expect_date(parser: &DateParser, text: &OsStr, zone: Zone, seconds: i64) -> io::Result<()> {
        let actual = parser.parse(text, zone)?;
        check(
            actual == seconds,
            format!("{text:?}: expected {seconds}, received {actual}"),
        )
    }
    fn child(name: &str) -> io::Result<()> {
        select(name)?;
        let parser = capture()?;
        let custom_automation_id = if name == "en-001" {
            let name: Vec<_> = name.encode_utf16().chain([0]).collect();
            #[expect(
                unsafe_code,
                reason = "The terminated supplemental-culture fixture stays live through a read-only scalar LCID query"
            )]
            // SAFETY: this query neither installs a locale nor retains a pointer.
            let id =
                unsafe { windows_sys::Win32::Globalization::LocaleNameToLCID(name.as_ptr(), 0) };
            check(
                id != 0,
                "supplemental culture has no native LCID observation",
            )?;
            matches!(id, 0x0c00 | 0x1000 | 0x1400)
        } else {
            false
        };
        for (text, seconds) in [
            ("1970-01-01", 0),
            ("2000-02-29", 951_782_400),
            ("2024", 1_704_067_200),
            ("2024-01", 1_704_067_200),
            ("2024-01-01T12:34:56", 1_704_112_496),
        ] {
            expect_date(&parser, OsStr::new(text), Zone::Utc, seconds)?;
            expect_date(&parser, OsStr::new(text), Zone::Local, seconds)?;
        }
        // This fixture exercises native localized weekday/month text, including
        // German's non-ASCII March name, plus each locale's numeric date ordering.
        let locale = LocaleSnapshot::named(name.as_bytes())?;
        let calendar = Calendar::from_epoch(1_709_296_496, Zone::Utc)?;
        let ctime = calendar.format_in(OsStr::new("%a %b %d %H:%M:%S %Y"), 256, &locale)?;
        expect_date(&parser, &ctime, Zone::Utc, 1_709_296_496)?;
        if name.starts_with("de-") || name.starts_with("German_") {
            let decomposed =
                calendar.format_in(OsStr::new("%a Ma\u{308}rz %d %H:%M:%S %Y"), 256, &locale)?;
            expect_date(&parser, &decomposed, Zone::Utc, 1_709_296_496)?;
        }
        let short = calendar.format_in(OsStr::new("%x"), 256, &locale)?;
        let composite = calendar.format_in(OsStr::new("%c"), 256, &locale)?;
        expect_date(&parser, &short, Zone::Local, 1_709_251_200)?;
        expect_date(&parser, &composite, Zone::Local, 1_709_296_496)?;
        if custom_automation_id {
            use std::os::windows::ffi::{OsStrExt, OsStringExt};
            let digits: Vec<_> = short
                .encode_wide()
                .map(|unit| {
                    if (u16::from(b'0')..=u16::from(b'9')).contains(&unit) {
                        0xff10 + unit - u16::from(b'0')
                    } else {
                        unit
                    }
                })
                .collect();
            expect_date(
                &parser,
                &std::ffi::OsString::from_wide(&digits),
                Zone::Local,
                1_709_251_200,
            )?;
        }
        // Later native selection cannot change a retained parser's interpretation.
        select(if name == "C" { "de-DE" } else { "C" })?;
        expect_date(&parser, &ctime, Zone::Utc, 1_709_296_496)?;
        expect_date(&parser, &short, Zone::Local, 1_709_251_200)?;
        for text in [
            "",
            "2100-02-29",
            "2024-02-31",
            "2024-01-01 trailing",
            "a\0b",
        ] {
            let error = parser
                .parse(OsStr::new(text), Zone::Utc)
                .err()
                .ok_or_else(|| io::Error::other(format!("invalid date accepted: {text:?}")))?;
            check(
                error.kind() == io::ErrorKind::InvalidInput,
                "invalid date error category changed",
            )?;
        }
        check(
            parser
                .parse(OsStr::new(&"a".repeat(32768)), Zone::Utc)
                .is_err(),
            "oversized date accepted",
        )?;
        let error = parser
            .parse(OsStr::new("not a date"), Zone::Utc)
            .err()
            .ok_or_else(|| io::Error::other("invalid native date accepted"))?;
        if custom_automation_id {
            check(
                error.kind() == io::ErrorKind::InvalidInput && error.raw_os_error().is_none(),
                "named NLS picture mismatch became a capability or native error",
            )?;
        } else {
            let automation = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<AutomationDateError>())
                .ok_or_else(|| io::Error::other("native date error lost its HRESULT domain"))?;
            check(
                automation.status() < 0 && error.raw_os_error().is_none(),
                "HRESULT became Win32 errno",
            )?;
        }
        expect_date(&parser, OsStr::new("3001-01-01"), Zone::Utc, 32_535_216_000)?;
        expect_date(
            &parser,
            OsStr::new("9999-01-01"),
            Zone::Utc,
            253_370_764_800,
        )?;
        for (text, seconds) in [
            ("1969-12-30", -172800),
            ("3001-01-01", 32_535_216_000),
            ("10000-01-01", 253_402_300_800),
        ] {
            expect_date(&parser, OsStr::new(text), Zone::Local, seconds)?;
            expect_date(&parser, OsStr::new(text), Zone::Utc, seconds)?;
            let calendar = Calendar::from_epoch(seconds, Zone::Local)?;
            let numeric = calendar.format_in(OsStr::new("%F %T %z %Z"), 128, &locale)?;
            check(!numeric.is_empty(), "expanded local calendar has no output")?;
        }
        Ok(())
    }
    pub(super) fn run() -> io::Result<()> {
        if let Some(name) = std::env::args().nth(1) {
            return child(&name);
        }
        for name in [
            "C",
            "en_US.UTF8",
            "en-CA",
            "de-DE",
            "German_Germany.1252",
            "fr-FR",
            "French_France.1252",
            "en-001",
        ] {
            let output = Command::new(std::env::current_exe()?)
                .arg(name)
                .env("TZ", "UTC0")
                .output()?;
            check(
                output.status.success(),
                format!(
                    "native date child {name}: {}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            )?;
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
