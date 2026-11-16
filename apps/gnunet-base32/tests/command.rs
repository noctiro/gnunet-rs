//! Native executable streaming, validation-before-output and spool cleanup.
use std::{
    error::Error,
    ffi::OsStr,
    fs, io,
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
type Failure = Box<dyn Error>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let root = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("base32-native-{:032x}", u128::from_be_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&root)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(root.join(name)))
    }
    fn run(&self, input: &[u8], args: &[&str]) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), Failure> {
        let source = self.0.join("input");
        let stdout = self.0.join("stdout");
        let stderr = self.0.join("stderr");
        fs::write(&source, input)?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-base32"));
        command.env_clear();
        for key in ["SystemRoot", "WINDIR", "PATH", "PATHEXT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in ["TMPDIR", "TMP", "TEMP"] {
            command.env(key, &self.0);
        }
        let mut child = command
            .current_dir(&self.0)
            .args(args)
            .stdin(fs::File::open(source)?)
            .stdout(Stdio::from(fs::File::create(&stdout)?))
            .stderr(Stdio::from(fs::File::create(&stderr)?))
            .spawn()?;
        let hard = Instant::now() + Duration::from_secs(60);
        let status = (|| -> io::Result<ExitStatus> {
            loop {
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
                if Instant::now() >= hard {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Base32 did not exit",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        let status = match status {
            Ok(status) => status,
            Err(original) => {
                let kill = child.kill();
                let reap = child.wait();
                return Err(
                    format!("{original}; original child kill={kill:?}; reap={reap:?}").into(),
                );
            }
        };
        Ok((status, fs::read(stdout)?, fs::read(stderr)?))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn native_streams_validate_before_output_and_remove_the_spool() -> Result<(), Failure> {
    let directory = Directory::new()?;
    for (input, args, expected) in [
        (b"hello".as_slice(), &[][..], b"D1JPRV3F".as_slice()),
        (b"dijprv3f", &["-d"][..], b"hello"),
        (b"", &["-d"][..], b""),
    ] {
        let (status, output, errors) = directory.run(input, args)?;
        if !status.success() || output != expected {
            return Err(format!("Base32 golden: {status}; {errors:?}; {output:?}").into());
        }
    }
    // Multiple conversion groups and native worker chunks, including all byte
    // values and residual bits. No Unicode or newline conversion is allowed.
    let input: Vec<_> = (0..16_643).map(|i| (i % 256) as u8).collect();
    let (status, encoded, errors) = directory.run(&input, &[])?;
    if !status.success() {
        return Err(format!("Base32 encode: {status}; {errors:?}").into());
    }
    let (status, decoded, errors) = directory.run(&encoded, &["-d"])?;
    if !status.success() || decoded != input {
        return Err(format!("Base32 roundtrip: {status}; {errors:?}").into());
    }
    let mut malformed = encoded;
    malformed.push(b'_');
    let (status, output, errors) = directory.run(&malformed, &["-d"])?;
    if status.code() != Some(3) || !output.is_empty() {
        return Err(format!("malformed Base32 exposed stdout: {status}; {errors:?}").into());
    }
    for entry in fs::read_dir(&directory.0)? {
        if entry?
            .file_name()
            .to_string_lossy()
            .starts_with("gnunet-base32-")
        {
            return Err("original Base32 spool namespace was not removed".into());
        }
    }
    Ok(())
}
