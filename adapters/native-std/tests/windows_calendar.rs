//! Native Windows calendar conversion, UTC zone policy and wide output bounds.
#![cfg(windows)]
use gnunet_native::{
    calendar::{Calendar, Zone},
    locale::LocaleSnapshot,
};
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent UTC/Gregorian literals check native conversion and prevent local-zone leakage in UTC output"
)]
fn utc_and_explicit_locale_keep_calendar_zone_and_wide_literals() -> io::Result<()> {
    let utc = Calendar::from_epoch(1_700_000_000, Zone::Utc)?;
    let c = LocaleSnapshot::named(b"C")?;
    assert_eq!(
        utc.format_in(OsStr::new("%FT%T %z %Z %%z %#z"), 128, &c)?,
        "2023-11-14T22:13:20 +0000 UTC %z +0000"
    );
    assert_eq!(
        utc.format_in(OsStr::new("%a %b %d %G-%V-%u"), 128, &c)?,
        "Tue Nov 14 2023-46-2"
    );
    assert_eq!(
        Calendar::from_epoch(1_609_459_200, Zone::Utc)?.format_in(
            OsStr::new("%G-%V-%u"),
            32,
            &c
        )?,
        "2020-53-5"
    );
    assert_eq!(utc.format_in(OsStr::new(""), 1, &c)?, OsString::new());
    assert_eq!(utc.format_in(OsStr::new("%Y"), 5, &c)?, "2023");
    let wide = OsString::from_wide(&[0xd800, 0x4e2d, b'%' as u16, b'Y' as u16, 0xdc00]);
    let formatted = utc.format_in(&wide, 32, &c)?;
    assert_eq!(
        formatted.encode_wide().collect::<Vec<_>>(),
        [0xd800, 0x4e2d, 0x32, 0x30, 0x32, 0x33, 0xdc00]
    );
    // Explicit locale selection never installs a global/thread locale.
    let german = LocaleSnapshot::named(b"de-DE")?;
    assert_eq!(utc.format_in(OsStr::new("%B"), 64, &german)?, "November");
    assert_eq!(utc.format_in(OsStr::new("%A"), 64, &german)?, "Dienstag");
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Malformed formats and range/capacity errors are ordinary failures, never invalid-parameter-handler process termination"
)]
fn invalid_native_formats_and_ranges_fail_without_global_error_handlers() -> io::Result<()> {
    let utc = Calendar::from_epoch(1_700_000_000, Zone::Utc)?;
    for pattern in ["%", "%#", "%n%Q", "%Q", "%##Y", "%EY"] {
        assert_eq!(
            utc.format(OsStr::new(pattern), 64).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let nul = OsString::from_wide(&[b'Y' as u16, 0, b'Z' as u16]);
    assert!(utc.format(&nul, 64).is_err());
    assert!(utc.format(OsStr::new("%Y"), 4).is_err());
    assert!(utc.format(OsStr::new(""), 0).is_err());
    assert!(utc.format(OsStr::new("x"), 32769).is_err());
    let error = Calendar::from_epoch(i64::MAX, Zone::Utc)
        .err()
        .ok_or_else(|| io::Error::other("out-of-range calendar was accepted"))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.raw_os_error(), None);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Signed and expanded-year UTC fixtures must not be narrowed to the native 1970..3000 epoch"
)]
fn full_protocol_years_keep_real_numeric_and_iso_week_fields() -> io::Result<()> {
    let c = LocaleSnapshot::named(b"C")?;
    for (seconds, expected) in [
        (-1, "1969-12-31T23:59:59 +0000 UTC"),
        (-62_135_596_800, "0001-01-01T00:00:00 +0000 UTC"),
        (32_535_216_000, "3001-01-01T00:00:00 +0000 UTC"),
        (253_402_300_800, "10000-01-01T00:00:00 +0000 UTC"),
    ] {
        assert_eq!(
            Calendar::from_epoch(seconds, Zone::Utc)?.format_in(
                OsStr::new("%FT%T %z %Z"),
                128,
                &c
            )?,
            expected
        );
    }
    let protocol = (u64::MAX / 1_000_000) as i64;
    let rendered = Calendar::from_epoch(protocol, Zone::Utc)?.format_in(
        OsStr::new("%Y-%m-%d %G-%V-%u"),
        128,
        &c,
    )?;
    assert!(!rendered.is_empty());
    Ok(())
}
