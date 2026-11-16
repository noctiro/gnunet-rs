//! Native listing fixtures only; no PF command, device or policy mutation.
use super::*;

#[test]
fn native_scope_must_be_present_and_unskipped_including_the_new_tun() -> io::Result<()> {
    let coverage = Coverage::parse(b"all\nem0\nlo0 (skip)\ntun7\nunused (skip)\n")?;
    coverage.require(b"em0")?;
    coverage.require(b"tun7")?;
    for (name, kind) in [
        (&b"lo0"[..], io::ErrorKind::PermissionDenied),
        (&b"tun8"[..], io::ErrorKind::NotConnected),
        (&b"em"[..], io::ErrorKind::NotConnected),
    ] {
        if !coverage
            .require(name)
            .is_err_and(|error| error.kind() == kind)
        {
            return Err(io::Error::other("PF interface coverage scope changed"));
        }
    }
    Ok(())
}

#[test]
fn a_malformed_later_row_never_qualifies_a_successful_prefix() -> io::Result<()> {
    for suffix in [
        "lo0",
        "lo0 (skip) trailing\n",
        "lo0 (unknown)\n",
        "lo0\0\n",
        "\tlo0\n",
        "em0 (skip)\n",
        "0123456789abcdef\n",
        "\n",
    ] {
        if Coverage::parse(format!("em0\n{suffix}").as_bytes()).is_ok() {
            return Err(io::Error::other("PF accepted a partial interface listing"));
        }
    }
    if Coverage::parse(&[]).is_ok() {
        return Err(io::Error::other("empty output certified PF coverage"));
    }
    Ok(())
}
