//! Real public date conversion in fresh children with a controlled native timezone.
use gnunet_program_host::helpers::parse_absolute;
use std::{io, process::Command};

fn child() -> io::Result<()> {
    for (input, micros) in [
        (b"1970-01-01".as_slice(), 0),
        (b"2024-02-29", 1_709_164_800_000_000),
        (b"Mon Jan 01 12:34:56 2024", 1_704_112_496_000_000),
        (b"2024-01-01 12:34", 1_704_112_440_000_000),
        (b"2024-01-01\0ignored", 1_704_067_200_000_000),
        (b"10000", 10_000_000_000),
        (b"END OF TIME", u64::MAX),
        (b"18446744073709551615", u64::MAX),
    ] {
        if parse_absolute(input) != Ok(micros) {
            return Err(io::Error::other(format!(
                "date contract changed for {input:?}"
            )));
        }
    }
    for input in [
        b"not a date".as_slice(),
        b"2024-01-01 trailing",
        b"2024-01-01 12:34:xx",
    ] {
        if parse_absolute(input).is_ok() {
            return Err(io::Error::other(format!(
                "incomplete date was accepted: {input:?}"
            )));
        }
    }
    Ok(())
}
fn main() -> io::Result<()> {
    if std::env::args_os().nth(1).is_some() {
        return child();
    }
    let output = Command::new(std::env::current_exe()?)
        .arg("date-child")
        .env("TZ", "UTC0")
        .env("LC_ALL", "C")
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "date child {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}
