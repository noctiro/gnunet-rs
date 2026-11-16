//! Public command parsing retains local non-Unicode strings without replacement.
use gnunet_native::os_bytes;
use gnunet_program_host::{
    getopt::{Options, append_environment},
    helpers::{self, Target},
};
use std::ffi::OsString;
#[cfg(windows)]
use std::io;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The public parser must keep option callback bytes and final argument permutation across native encoding boundaries"
)]
fn native_option_values_and_environment_tokens_remain_lossless()
-> Result<(), Box<dyn std::error::Error>> {
    let local = b"\xed\xa0\x80-\xe4\xb8\xad-\xf0\x9f\x9a\x80-\xed\xb0\x80";
    let native = os_bytes::decode(local)?.into_owned();
    let target = Target::new(None);
    let mut options = Options::new();
    options.add(helpers::string(
        b'o',
        b"output",
        b"VALUE",
        b"native value",
        target.clone(),
    ));
    let run = options.run(
        b"tool",
        [
            "tool".into(),
            "left".into(),
            "-o".into(),
            native.clone(),
            "right".into(),
        ],
        false,
    );
    assert_eq!(target.get()?, Some(local.to_vec()));
    assert_eq!(
        run.remaining(),
        Some(&[b"left".to_vec(), b"right".to_vec()][..])
    );
    assert!(run.output.failure.is_none());
    let mut environment = b"  ".to_vec();
    environment.extend_from_slice(local);
    environment.extend_from_slice(b" \t\"tail\"  ");
    let args = append_environment([OsString::from("tool")], Some(&environment))?;
    assert_eq!(
        args,
        [OsString::from("tool"), native, OsString::from("\t\"tail\"")]
    );
    Ok(())
}

#[cfg(windows)]
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Malformed Windows local bytes fail atomically instead of becoming replacement characters in arguments"
)]
fn malformed_windows_environment_does_not_return_partial_arguments() -> io::Result<()> {
    let error = append_environment([OsString::from("tool")], Some(b"valid \xff"))
        .err()
        .ok_or_else(|| io::Error::other("malformed argument was accepted"))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    Ok(())
}
