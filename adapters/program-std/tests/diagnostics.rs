//! Literal safe Rust diagnostic parsing controls. The original C %x/int* call is
//! source-only and is never executed or credited as a compatible scanf oracle.
use gnunet_program_host::diagnostics::{hex_to_bytes, print_bytes};
#[test]
fn bounded_hex_preserves_prior_assignments_inverse_tail_and_c_string_prefix() {
    let mut out = [0xa5; 8];
    assert_eq!(hex_to_bytes(b"ab cD 0xEE -f +3 z", &mut out, false), 6);
    assert_eq!(out, [0xab, 0xcd, 0, 0xee, 0xf1, 3, 0xa5, 0xa5]);
    let mut inverse = [0xa5; 5];
    assert_eq!(hex_to_bytes(b"0123bad", &mut inverse, true), 4);
    assert_eq!(inverse, [0xa5, 0x0d, 0xba, 0x23, 1]);
    let mut prefix = [0xa5; 3];
    assert_eq!(hex_to_bytes(b"ffzz11", &mut prefix, false), 1);
    assert_eq!(prefix, [0xff, 0xa5, 0xa5]);
    assert_eq!(hex_to_bytes(b"12\0ab", &mut prefix, false), 1);
    assert_eq!(prefix, [0x12, 0xa5, 0xa5]);
    assert_eq!(hex_to_bytes(b"ab", &mut [], false), 0);
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent literal fold/reversal outputs are asserted after the fallible writer operation"
)]
fn byte_printer_negative_fold_reverse_and_empty_are_exact() -> std::io::Result<()> {
    let mut output = Vec::new();
    print_bytes(&[0, 1, 0xff, 3, 4], -2, true, &mut output)?;
    assert_eq!(output, b"0403\nff01\n00\n");
    output.clear();
    print_bytes(&[], 0, false, &mut output)?;
    assert_eq!(output, b"\n");
    Ok(())
}

#[test]
fn source_relative_string_rounding_flag_preserves_exact_unrounded_speedup_values() {
    use gnunet_program_host::diagnostics::relative_time;
    assert_eq!(relative_time(10_001, false), b"10001 \xc2\xb5s");
    assert_eq!(relative_time(10_001, true), b"10 ms");
    assert_eq!(relative_time(3_600_000_000, false), b"1 h");
    assert_eq!(relative_time(86_400_000_000, false), b"1 day");
    assert_eq!(relative_time(0, false), b"0 ms");
    assert_eq!(relative_time(u64::MAX, false), b"forever");
}
