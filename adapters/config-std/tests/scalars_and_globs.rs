//! Public scalar conversions and wildcard includes at their final boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests compare public conversions and real file inclusion"
)]

use gnunet_config::{Configuration, Error, parse_size};
use std::{
    ffi::OsStr,
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[test]
fn decimal_and_binary_sizes_reach_public_configuration_values() -> Result<(), Error> {
    let mut config = Configuration::default();
    for (value, expected) in [
        (b"1GB".as_slice(), 1_000_000_000),
        (b"1TB", 1_000_000_000_000),
        (b"2PB", 2_000_000_000_000_000),
        (b"3EB", 3_000_000_000_000_000_000),
        (b"1TiB", 1 << 40),
        (b"1PiB", 1 << 50),
        (b"1EiB", 1 << 60),
        (b"1TB 2PB 3EB", 3_002_001_000_000_000_000),
        (b"18446744073709551615 KiB", u64::MAX - 1023),
    ] {
        assert_eq!(parse_size(value)?, expected, "{value:?}");
        config.set_value(b"limits", b"size", Some(value))?;
        assert_eq!(config.get_size(b"limits", b"size")?, expected, "{value:?}");
    }
    Ok(())
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-config-glob-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}

#[test]
fn wildcard_includes_can_consume_the_complete_remaining_filename()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = Directory::new()?;
    let fragments = directory.0.join("fragments");
    fs::create_dir(&fragments)?;
    for name in ["test0", "test1", "a", "abc", "a.conf"] {
        fs::write(fragments.join(name), format!("[files]\n{name}=included\n"))?;
    }
    let main = directory.0.join("main.conf");
    for (pattern, expected) in [
        ("test*", ["test0", "test1"].as_slice()),
        ("*", ["a", "a.conf", "abc", "test0", "test1"].as_slice()),
        ("*.conf", ["a.conf"].as_slice()),
        ("a*", ["a", "a.conf", "abc"].as_slice()),
        ("abc*", ["abc"].as_slice()),
        ("a*c", ["abc"].as_slice()),
        ("*b*", ["abc"].as_slice()),
        ("x*", [].as_slice()),
    ] {
        fs::write(&main, format!("@INLINE-MATCHING@ fragments/{pattern}\n"))?;
        let mut config = Configuration::default();
        config.parse(&main)?;
        let included = config
            .loaded_files()
            .iter()
            .skip(1)
            .map(|source| source.filename.file_name().ok_or(Error::InvalidInput))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            included,
            expected.iter().map(OsStr::new).collect::<Vec<_>>(),
            "{pattern}",
        );
        assert_eq!(
            config
                .sections()
                .map(|section| section.entries().len())
                .sum::<usize>(),
            expected.len(),
            "{pattern}",
        );
    }
    Ok(())
}
