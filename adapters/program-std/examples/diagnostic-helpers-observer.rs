//! Defined-safe public diagnostic helper counterpart, using owned output bytes.
use gnunet_program_host::{
    diagnostics::{self, Address},
    logging::{Environment, Logger, Stamp},
    policy::Level,
    shared_clock::SharedClock,
};
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
};
fn hex(v: &[u8]) -> String {
    let d = b"0123456789abcdef";
    let mut s = String::new();
    for b in v {
        s.push(char::from(d[usize::from(b >> 4)]));
        s.push(char::from(d[usize::from(b & 15)]));
    }
    s
}
fn row(out: &mut impl Write, name: &str, v: &[u8]) -> io::Result<()> {
    writeln!(out, "S {name} {}", hex(v))
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let key = std::array::from_fn(|i| i as u8);
    row(&mut out, "B2S", &diagnostics::bytes_short(b"some data"))?;
    for name in ["H2S", "H2S2"] {
        row(&mut out, name, &diagnostics::hash_short(&[0; 64]))?;
    }
    row(&mut out, "HFULL", &diagnostics::hash_full(&[0; 64]))?;
    row(
        &mut out,
        "SHORT",
        &diagnostics::short_hash_short(&[255; 32]),
    )?;
    row(&mut out, "UUID", &diagnostics::uuid_short(&[0x25; 16]))?;
    for name in ["P2S", "P2S2", "E2S", "E2S2"] {
        row(&mut out, name, &diagnostics::public_key_short(&key))?;
    }
    for name in ["I2S", "I2S2"] {
        row(&mut out, name, &diagnostics::peer_short(Some(&key)))?;
    }
    row(&mut out, "IFULL", &diagnostics::peer_full(&key))?;
    for name in ["INULL", "INULL2"] {
        row(&mut out, name, &diagnostics::peer_short(None))?;
    }
    row(&mut out, "ANULL", &diagnostics::address(Address::Unknown)?)?;
    row(
        &mut out,
        "UNSUPPORTED",
        &diagnostics::address(Address::Unsupported)?,
    )?;
    for (name, port, valid_size) in [
        ("V4", 0, true),
        ("V4PORT", 65535, true),
        ("V4BAD", 65535, false),
    ] {
        row(
            &mut out,
            name,
            &diagnostics::address(Address::V4 {
                ip: [127, 0, 0, 42].into(),
                port,
                valid_size,
            })?,
        )?;
    }
    for name in [
        "::",
        "::1",
        "::192.0.2.1",
        "::ffff:192.0.2.1",
        "2001:db8:0:1:0:0:0:1",
        "1:0:0:2:0:0:3:4",
    ] {
        let ip = name.parse()?;
        for (kind, port, valid_size) in
            [("V6", 0, true), ("V6PORT", 53, true), ("V6BAD", 53, false)]
        {
            row(
                &mut out,
                kind,
                &diagnostics::address(Address::V6 {
                    ip,
                    port,
                    valid_size,
                })?,
            )?;
        }
    }
    let mut un = vec![
        0;
        std::mem::size_of::<libc::sockaddr_un>()
            - std::mem::offset_of!(libc::sockaddr_un, sun_path)
    ];
    un[..12].copy_from_slice(b"/owned/file\0");
    row(
        &mut out,
        "UNIX",
        &diagnostics::address(Address::Unix {
            path: &un,
            length: std::mem::size_of::<libc::sockaddr_un>(),
        })?,
    )?;
    un.fill(0);
    un[1..10].copy_from_slice(b"abstract\0");
    row(
        &mut out,
        "ABSTRACT",
        &diagnostics::address(Address::Unix {
            path: &un,
            length: std::mem::size_of::<libc::sockaddr_un>(),
        })?,
    )?;
    row(
        &mut out,
        "UNBOUND",
        &diagnostics::address(Address::Unix {
            path: &un,
            length: std::mem::size_of::<libc::sa_family_t>(),
        })?,
    )?;
    let mut logger = Logger::new(b"owned-helper", std::process::id(), true)?;
    writeln!(out, "SCOPE_ROOT {}", u8::from(logger.scope_get().is_none()))?;
    let old = logger.scope_enter([0x33; 16]);
    writeln!(
        out,
        "SCOPE_ENTER {}",
        u8::from(logger.scope_get() == Some([0x33; 16]))
    )?;
    let fresh = Logger::scope_fresh_os()?;
    let saved = logger.scope_enter(fresh);
    writeln!(
        out,
        "SCOPE_FRESH {}",
        u8::from(logger.scope_get() == Some(fresh))
    )?;
    logger.scope_restore(saved);
    logger.scope_restore(old);
    writeln!(
        out,
        "SCOPE_RESTORE {}",
        u8::from(logger.scope_get().is_none())
    )?;
    for fold in [0, 3, -3, i32::MIN] {
        for inverse in [false, true] {
            writeln!(out, "PRINT {fold} {}", u8::from(inverse))?;
            diagnostics::print_bytes(&[0, 1, 2, 127, 128, 254, 255], fold, inverse, &mut out)?;
            writeln!(out, "PRINT_END")?;
        }
    }
    let clock = SharedClock::native(0)?;
    let mut stderr = Vec::new();
    logger.setup_routed(
        b"owned-helper",
        Some(b"DEBUG"),
        None,
        &Environment::capture(),
        &Stamp::setup_now()?,
        &mut stderr,
    )?;
    let records = Rc::new(RefCell::new(Vec::new()));
    let keep = Rc::clone(&records);
    let token = logger.logger_add(move |record| {
        drop(writeln!(
            &mut *keep.borrow_mut(),
            "R {} {} {} {}",
            record.kind.0,
            hex(record.component),
            hex(record.date),
            hex(record.message)
        ));
    })?;
    logger.config_missing(
        Level::ERROR,
        b"own%section",
        b"missing%key",
        &clock,
        &mut stderr,
    )?;
    logger.config_invalid(
        Level::WARNING,
        b"own%section",
        b"key",
        b"required%data",
        &clock,
        &mut stderr,
    )?;
    logger.log_skip_routed(3, false, &clock, &mut stderr)?;
    out.extend_from_slice(&records.borrow());
    records.borrow_mut().clear();
    writeln!(out, "SKIP {}", logger.get_log_skip())?;
    logger.log_skip_routed(0, true, &clock, &mut stderr)?;
    out.extend_from_slice(&records.borrow());
    writeln!(out, "SKIP {}", logger.get_log_skip())?;
    logger.logger_remove(token)?;
    io::stdout().write_all(&out)?;
    io::stderr().write_all(&stderr)?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}
