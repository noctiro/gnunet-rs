//! Differential fixtures emitted by original pinned C parser/scalar functions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible differential tests compare independently executed original C outputs"
)]
use gnunet_config::{
    Configuration, Environment, Error, parse_number, parse_relative_time, parse_size,
};
use std::{fmt::Write, io, path::PathBuf};
struct Env;
impl Environment for Env {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        if name == b"ORACLE_ENV" {
            Some(b"/env".to_vec())
        } else {
            None
        }
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(PathBuf::from("/cwd"))
    }
}
fn hex(input: &[u8]) -> String {
    let mut result = String::new();
    for byte in input {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}
#[test]
fn original_c_parser_scalars_and_expansion_match_all_44_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut actual = String::new();
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x23\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x0a\x5b\x46\x69\x72\x73\x74\x5d\x0a\x61\x20\x3d\x20\x31\x0a\x62\x3d\x22\x74\x77\x6f\x22\x0a\x5b\x53\x45\x43\x4f\x4e\x44\x5d\x0a\x6b\x65\x79\x3d\x78\x0a\x5b\x66\x69\x72\x73\x74\x5d\x0a\x41\x20\x3d\x20\x63\x68\x61\x6e\x67\x65\x64\x0a",None);
        writeln!(
            actual,
            "parser|basic|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x5b\x73\x5d\x0a\x62\x79\x74\x65\x73\x3d\xff\xfe\x0a\x65\x6d\x70\x74\x79\x20\x3d\x0a\x71\x75\x6f\x74\x65\x3d\x22\x0a\x73\x6c\x61\x73\x68\x65\x73\x3d\x6f\x6e\x65\x5c\x6e\x74\x77\x6f\x0a",None);
        writeln!(
            actual,
            "parser|opaque|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x20\x20\x23\x20\x69\x67\x6e\x6f\x72\x65\x64\x0a\x25\x69\x67\x6e\x6f\x72\x65\x64\x0a\x5b\x73\x5d\x0a\x09\x6b\x65\x79\x09\x3d\x09\x20\x76\x61\x6c\x75\x65\x09\x77\x69\x74\x68\x09\x74\x61\x62\x73\x0d\x0a\x69\x6e\x6c\x69\x6e\x65\x20\x3d\x20\x76\x61\x6c\x75\x65\x20\x23\x20\x72\x65\x74\x61\x69\x6e\x65\x64\x0a",None);
        writeln!(
            actual,
            "parser|whitespace|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x5b\x73\x5d\x0a\x66\x69\x72\x73\x74\x3d\x6f\x6b\x0a\x74\x68\x69\x73\x20\x69\x73\x20\x69\x6e\x76\x61\x6c\x69\x64\x0a\x73\x65\x63\x6f\x6e\x64\x3d\x69\x67\x6e\x6f\x72\x65\x64\x0a",None);
        writeln!(
            actual,
            "parser|partial_error|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x66\x69\x72\x73\x74\x3d\x69\x6e\x76\x61\x6c\x69\x64\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|option_no_section|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x3b\x6e\x6f\x74\x20\x61\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|semicolon|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x5b\x73\x5d\x20\x0a\x78\x3d\x6e\x6f\x74\x20\x61\x70\x70\x6c\x69\x65\x64\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|trailing_section_space|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x20\x5b\x73\x5d\x0a\x78\x3d\x6e\x6f\x74\x20\x61\x70\x70\x6c\x69\x65\x64\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|leading_section_space|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(b"\x5b\x5d\x0a\x3d\x76\x61\x6c\x75\x65\x0a", None);
        writeln!(
            actual,
            "parser|empty_section_key|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x5b\x73\x5d\x0a\x78\x3d\x22\x75\x6e\x74\x65\x72\x6d\x69\x6e\x61\x74\x65\x64\x0a\x79\x3d\x62\x61\x72\x65\x22\x0a",None);
        writeln!(
            actual,
            "parser|missing_quote|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x5b\x75\x6e\x75\x73\x65\x64\x5d\x0a\x5b\x73\x5d\x0a\x78\x3d\x31\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|empty_header|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result=cfg.deserialize(b"\x5b\x73\x5d\x0a\x78\x3d\x31\x0a\x40\x55\x4e\x4b\x4e\x4f\x57\x4e\x40\x20\x68\x65\x72\x65\x0a",None);
        writeln!(
            actual,
            "parser|unknown_directive|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let mut cfg = Configuration::default();
        let result = cfg.deserialize(
            b"\x40\x49\x4e\x4c\x49\x4e\x45\x40\x20\x61\x62\x73\x65\x6e\x74\x0a",
            None,
        );
        writeln!(
            actual,
            "parser|inline_no_source|{}|{}",
            if result.is_ok() { 1 } else { -1 },
            hex(&cfg.serialize()?)
        )?;
    }
    {
        let result = parse_number(b"\x30");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|zero|{ret}|{number}")?;
    }
    {
        let result = parse_number(b"\x2d\x31");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|negative|{ret}|{number}")?;
    }
    {
        let result = parse_number(b"\x20\x2b\x34\x32\x20\x09");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|signed|{ret}|{number}")?;
    }
    {
        let result = parse_number(b"\x31\x78");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|suffix|{ret}|{number}")?;
    }
    {
        let result = parse_number(b"\x30\x78\x31\x30");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|hex|{ret}|{number}")?;
    }
    {
        let result = parse_number(b"");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|empty|{ret}|{number}")?;
    }
    {
        let result = parse_number(
            b"\x31\x38\x34\x34\x36\x37\x34\x34\x30\x37\x33\x37\x30\x39\x35\x35\x31\x36\x31\x35",
        );
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "number|maximum|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"\x31\x4b\x69\x42\x20\x32\x20\x6b\x42\x20\x33\x42");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|mixed|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"\x31\x54\x42");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|legacy_tb|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|empty|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"\x32\x6b\x42\x20\x4d\x69\x42");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|multiply_units|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"\x2d\x31\x42");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|negative|{ret}|{number}")?;
    }
    {
        let result=parse_size(b"\x31\x38\x34\x34\x36\x37\x34\x34\x30\x37\x33\x37\x30\x39\x35\x35\x31\x36\x31\x35\x20\x4b\x69\x42");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|overflow_wrap|{ret}|{number}")?;
    }
    {
        let result = parse_size(b"\x31\x20\x78\x62");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "size|invalid|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(
            b"\x31\x68\x20\x32\x6d\x69\x6e\x20\x33\x73\x20\x34\x6d\x73\x20\x35\x75\x73",
        );
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|mixed|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"\x46\x6f\x52\x65\x56\x65\x52");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|forever|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"\x31\x77\x20\x31\x79");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|week_year|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"\x31\x27\x20\x32\x22");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|quotes|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"\x73");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|unit_only|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|empty|{ret}|{number}")?;
    }
    {
        let result = parse_relative_time(b"\x31\x66\x6f\x72\x74\x6e\x69\x67\x68\x74");
        let (ret, number) = match result {
            Ok(number) => (1, number),
            Err(_) => (-1, 0),
        };
        writeln!(actual, "time|invalid|{ret}|{number}")?;
    }
    let mut cfg = Configuration::default();
    cfg.set_value(b"PATHS", b"ROOT", Some(b"/config"))?;
    cfg.set_value(b"PATHS", b"EMPTY", Some(b""))?;
    writeln!(
        actual,
        "expand|paths_precedence|1|{}",
        hex(&cfg.expand_dollar(b"\x24\x52\x4f\x4f\x54\x2f\x61", &Env)?)
    )?;
    writeln!(
        actual,
        "expand|braced|1|{}",
        hex(&cfg.expand_dollar(b"\x78\x24\x7b\x52\x4f\x4f\x54\x7d\x2f\x7a", &Env)?)
    )?;
    writeln!(
        actual,
        "expand|nested|1|{}",
        hex(&cfg.expand_dollar(
            b"\x24\x7b\x55\x4e\x53\x45\x54\x3a\x2d\x24\x7b\x52\x4f\x4f\x54\x7d\x7d\x2f\x7a",
            &Env
        )?)
    )?;
    writeln!(actual,"expand|unknown|1|{}",hex(&cfg.expand_dollar(b"\x24\x47\x4e\x55\x4e\x45\x54\x5f\x43\x4f\x4e\x46\x49\x47\x5f\x4f\x52\x41\x43\x4c\x45\x5f\x4d\x49\x53\x53\x49\x4e\x47\x2f\x78",&Env)?))?;
    writeln!(
        actual,
        "expand|unmatched|1|{}",
        hex(&cfg.expand_dollar(b"\x24\x7b\x52\x4f\x4f\x54\x2f\x78", &Env)?)
    )?;
    writeln!(
        actual,
        "expand|inside|1|{}",
        hex(&cfg.expand_dollar(
            b"\x61\x2f\x24\x4f\x52\x41\x43\x4c\x45\x5f\x45\x4e\x56\x2f\x7a",
            &Env
        )?)
    )?;
    writeln!(
        actual,
        "expand|empty_set|1|{}",
        hex(&cfg.expand_dollar(
            b"\x24\x7b\x45\x4d\x50\x54\x59\x3a\x2d\x64\x65\x66\x61\x75\x6c\x74\x7d\x2f\x7a",
            &Env
        )?)
    )?;
    writeln!(
        actual,
        "expand|separators|1|{}",
        hex(&cfg.expand_dollar(b"\x24\x52\x4f\x4f\x54\x5c\x66\x69\x6c\x65", &Env)?)
    )?;
    writeln!(
        actual,
        "expand|punctuation|1|{}",
        hex(&cfg.expand_dollar(b"\x24\x52\x4f\x4f\x54\x21", &Env)?)
    )?;
    writeln!(
        actual,
        "expand|doubled|1|{}",
        hex(&cfg.expand_dollar(b"\x24\x24\x52\x4f\x4f\x54", &Env)?)
    )?;
    assert_eq!(actual, include_str!("fixtures/functions.txt"));
    if let Some(path) = std::env::var_os("GNUNET_CONFIG_TRACE") {
        std::fs::write(path, actual)?;
    }
    Ok(())
}
#[test]
fn additional_typed_values_and_defined_rejections() -> Result<(), Error> {
    let mut cfg = Configuration::default();
    for (value, expected) in [(b"-1".as_slice(), u64::MAX), (b"+42", 42), (b" 0 ", 0)] {
        cfg.set_value(b"s", b"n", Some(value))?;
        assert_eq!(cfg.get_number(b"S", b"N")?, expected);
    }
    assert!(matches!(
        parse_number(b"18446744073709551616"),
        Err(Error::Overflow)
    ));
    assert!(matches!(parse_number(b"1 x"), Err(Error::InvalidValue)));
    for (value, expected) in [
        (b"0x1.8p2".as_slice(), 6.0f32),
        (b"0x0p9999", 0.0),
        (b" -0.5 ", -0.5),
        (b"inf", f32::INFINITY),
    ] {
        cfg.set_value(b"s", b"f", Some(value))?;
        assert_eq!(cfg.get_float(b"s", b"f")?, expected);
    }
    cfg.set_value(b"s", b"f", Some(b"nan(payload)"))?;
    assert!(cfg.get_float(b"s", b"f")?.is_nan());
    cfg.set_value(b"s", b"b", Some(b"yes"))?;
    assert!(cfg.get_yesno(b"s", b"b")?);
    cfg.set_value(b"s", b"b", Some(b"true"))?;
    assert!(cfg.get_yesno(b"s", b"b").is_err());
    cfg.set_value(b"s", b"data", Some(b"0410"))?;
    let mut data = [0; 2];
    cfg.get_data(b"s", b"data", &mut data)?;
    assert_eq!(data, [1, 2]);
    cfg.set_value(b"PATHS", b"LOOP", Some(b"$LOOP"))?;
    assert!(matches!(
        cfg.expand_dollar(b"$LOOP", &Env),
        Err(Error::Cycle)
    ));
    assert!(matches!(
        cfg.deserialize(b"[s]\nx=before\0after", None),
        Err(Error::InvalidInput)
    ));
    Ok(())
}
