//! Explicit trusted platform gettext boundary and ownership observer.
use gnunet_program_host::{
    format::{self, Argument as A},
    locale::{AbiProfile, ProcessLocale},
    program::{Failure, LocaleSetup},
};
use std::{
    io::{self, Write},
    path::PathBuf,
};
fn row(out: &mut impl Write, name: &str, value: &[u8]) -> io::Result<()> {
    write!(out, "{name} ")?;
    for b in value {
        write!(out, "{b:02x}")?;
    }
    out.write_all(b"\n")
}
fn main() -> Result<(), Failure> {
    let mut args = std::env::args_os().skip(1);
    let library = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("trusted gettext library required"))?,
    );
    let directory = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("owned catalog directory required"))?,
    );
    let profile = if args.next().is_some_and(|v| v == "libc") {
        AbiProfile::Libc
    } else {
        AbiProfile::Libintl
    };
    let absent_rejected = if let Some(absent) = std::env::var_os("OWNED_NLS_ABSENT") {
        let absent = PathBuf::from(absent);
        if absent.try_exists()? {
            return Err(io::Error::other("failure control path must be definitely absent").into());
        }
        #[expect(
            unsafe_code,
            reason = "Dedicated fresh exec supplies an owned definitely absent path; no native object or function can be used"
        )]
        // SAFETY: path is owned by this isolated fixture and remains absent;
        // dlopen cannot load or initialize any library on this exact path.
        let rejected = unsafe { ProcessLocale::load(absent, profile) }.is_err();
        if !rejected {
            return Err(io::Error::other("absent backend was not rejected").into());
        }
        true
    } else {
        false
    };
    #[expect(
        unsafe_code,
        reason = "This dedicated early single-thread exec is supplied a runner-hashed trusted standard gettext library and explicit ABI; no unrelated locale/environment users exist"
    )]
    // SAFETY: the runner certifies the native library/header ABI and this fresh process has no foreign locale users.
    let mut locale = unsafe { ProcessLocale::load(library.clone(), profile)? };
    let mut project = gnunet_config::ProjectData {
        gettext_domain: Some(b"gnunet".to_vec()),
        gettext_path: Some(directory),
        ..gnunet_config::ProjectData::default()
    };
    locale.configure(&project)?;
    project.gettext_domain = Some(b"owned-project".to_vec());
    locale.configure(&project)?;
    let result = locale
        .result()
        .ok_or_else(|| io::Error::other("actual native locale result missing"))?;
    let mut out = io::stdout();
    if absent_rejected {
        writeln!(out, "RUST_ABSENT_REJECTED 1")?;
    }
    writeln!(out, "SELECTED {}", i32::from(result.environment_selected))?;
    row(&mut out, "LOCALE", &result.messages_locale)?;
    row(&mut out, "DOMAIN", &result.domain)?;
    let translations = locale.translations();
    row(&mut out, "GET", &translations.gettext(None, b"Owned help")?)?;
    row(
        &mut out,
        "DGET",
        &translations.gettext(Some(b"gnunet"), b"ERROR")?,
    )?;
    row(
        &mut out,
        "FALLBACK",
        &translations.gettext(None, b"untranslated owned message")?,
    )?;
    for i in 0..3 {
        row(
            &mut out,
            &format!("NGET{i}"),
            &translations.ngettext(None, b"one item", b"many items", i)?,
        )?;
        row(
            &mut out,
            &format!("DNGET{i}"),
            &translations.ngettext(Some(b"gnunet"), b"one item", b"many items", i)?,
        )?;
    }
    let template = translations.gettext(
        Some(b"gnunet"),
        b"Option `%s' can't be used with other options.\n",
    )?;
    row(
        &mut out,
        "FORMAT",
        &format::render(&template, &[A::Bytes(b"raw%value")])?,
    )?;
    let template = translations.gettext(
        Some(b"gnunet"),
        b"Message `%.*s' repeated %u times in the last %s\n",
    )?;
    row(
        &mut out,
        "BULK",
        &format::render(
            &template,
            &[
                A::Signed(3),
                A::Bytes(b"abcdef"),
                A::Unsigned(42),
                A::Bytes(b"2 s"),
            ],
        )?,
    )?;
    let unsafe_template = translations.gettext(Some(b"gnunet"), b"unsafe source %s")?;
    row(&mut out, "UNSAFE_FORMAT_DATA_ONLY", &unsafe_template)?;
    let rejected = format::render(&unsafe_template, &[A::Bytes(b"value")]).is_err();
    writeln!(out, "RUST_UNSAFE_REJECTED {}", i32::from(rejected))?;
    drop(locale);
    #[expect(
        unsafe_code,
        reason = "Same trusted ABI and fresh-process exclusive context; the constructor must reject before loading while a translation Rc retains the capability"
    )]
    // SAFETY: only an already-held capability is being tested; no native configuration occurs on this expected failure.
    let held = unsafe { ProcessLocale::load(library.clone(), profile) }.is_err();
    writeln!(out, "RUST_RC_RETAINS_CAPABILITY {}", i32::from(held))?;
    row(
        &mut out,
        "RUST_AFTER_INSTALLER_DROP",
        &translations.gettext(None, b"Owned help")?,
    )?;
    drop(translations);
    #[expect(
        unsafe_code,
        reason = "All prior translation handles dropped, and the same certified backend is loaded under the same exclusive early-process contract"
    )]
    // SAFETY: no previous function/string use remains live; the backend is the same trusted standard implementation.
    let restored = unsafe { ProcessLocale::load(library, profile)? };
    drop(restored);
    writeln!(out, "RUST_LAST_RC_RELEASED 1")?;
    Ok(())
}
