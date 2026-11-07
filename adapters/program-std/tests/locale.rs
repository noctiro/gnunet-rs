//! Safe format/disabled-NLS contracts; actual native locale runs in fresh execs.
use gnunet_program_host::{
    format::{self, Argument as A},
    locale,
};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Literal source format values and positional translation order are independent expected outputs"
)]
fn reviewed_format_operands_preserve_bytes_positions_width_and_bulk_precision()
-> std::io::Result<()> {
    assert_eq!(
        format::render(
            b"%2$s:%1$08u %%",
            &[A::Unsigned(42), A::Bytes(b"raw%name\xff")]
        )?,
        b"raw%name\xff:00000042 %"
    );
    assert_eq!(
        format::render(
            b"[%.*s] %u",
            &[A::Signed(3), A::Bytes(b"abcdef"), A::Unsigned(7)]
        )?,
        b"[abc] 7"
    );
    assert_eq!(
        format::render(b"[%*s]", &[A::Signed(-5), A::Bytes(b"xy")])?,
        b"[xy   ]"
    );
    assert_eq!(
        format::render(b"%.0u/%+#08x", &[A::Unsigned(0), A::Unsigned(0x1f)])?,
        b"/0x00001f"
    );
    assert_eq!(format::render(b"%s", &[A::Bytes(b"one\0two")])?, b"one");
    Ok(())
}
#[test]
fn untrusted_translated_formats_never_write_through_pointers_or_succeed_with_wrong_types() {
    assert!(format::render(b"%n", &[A::Unsigned(1)]).is_err());
    assert!(format::render(b"%s", &[A::Signed(1)]).is_err());
    assert!(format::render(b"%3$s", &[A::Bytes(b"one")]).is_err());
    assert!(format::render_limited(b"%1000000s", &[A::Bytes(b"x")], 20).is_err());
    assert!(format::render_limited(b"%20sTAIL", &[A::Bytes(b"x")], 20).is_err());
    assert!(format::render(b"%999999999999999999999999999999s", &[A::Bytes(b"x")]).is_err());
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Disabled NLS is an explicit build profile, never fallback from a failed native backend"
)]
fn disabled_profile_owns_c_string_prefixes_and_source_plural_selection() -> std::io::Result<()> {
    let backend = locale::disabled();
    assert_eq!(backend.gettext(None, b"one\0two")?, b"one");
    assert_eq!(
        backend.ngettext(Some(b"gnunet"), b"one", b"many", 1)?,
        b"one"
    );
    assert_eq!(backend.ngettext(None, b"one", b"many", 0)?, b"many");
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Reject unsupported translated operand contracts without accepting accidental ABI shapes"
)]
fn wide_and_mixed_position_translations_are_errors_and_zero_alternate_forms_are_exact()
-> std::io::Result<()> {
    use gnunet_program_host::format::{Argument as A, render};
    assert!(render(b"%ls", &[A::Bytes(b"bytes")]).is_err());
    assert!(render(b"%lc", &[A::Character(b'x')]).is_err());
    assert!(render(b"%1$s %s", &[A::Bytes(b"first"), A::Bytes(b"second")]).is_err());
    assert!(render(b"%1$*s", &[A::Signed(3), A::Bytes(b"data")]).is_err());
    assert!(render(b"%*s", &[A::Signed(i64::MAX), A::Bytes(b"data")]).is_err());
    assert_eq!(
        render(
            b"%#.0o|%#.2x|%#.2X",
            &[A::Unsigned(0), A::Unsigned(0), A::Unsigned(0)]
        )?,
        b"0|00|00"
    );
    assert_eq!(
        render(b"%2$*1$s", &[A::Signed(5), A::Bytes(b"abc")])?,
        b"  abc"
    );
    Ok(())
}
