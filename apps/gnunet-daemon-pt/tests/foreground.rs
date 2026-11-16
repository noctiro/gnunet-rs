//! Normal executable startup and exit status; no service/device interoperability.
use std::{
    error::Error,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
type Failure = Box<dyn Error>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let root = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("pt-native-{:032x}", u128::from_be_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&root)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(root.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn execute(root: &Path, args: &[&OsStr]) -> Result<(ExitStatus, String, String), Failure> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-daemon-pt"));
    command.env_clear();
    for key in [
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut child = command
        .current_dir(root)
        .env("GNUNET_BASE_CONFIG", root.join("defaults"))
        .env("XDG_CONFIG_HOME", root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout)?)
        .stderr(fs::File::create(&stderr)?)
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(60);
    let result = (|| -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PT foreground did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    let status = match result {
        Ok(status) => status,
        Err(original) => {
            let kill = child.kill();
            let reap = child.wait();
            return Err(format!("{original}; original child kill={kill:?}; reap={reap:?}").into());
        }
    };
    Ok((
        status,
        fs::read_to_string(stdout)?,
        fs::read_to_string(stderr)?,
    ))
}
#[test]
fn disabled_program_and_option_errors_use_the_native_foreground() -> Result<(), Failure> {
    let directory = Directory::new()?;
    fs::create_dir(directory.0.join("defaults"))?;
    fs::write(directory.0.join("pt.conf"),b"[pt]\nTUNNEL_IPV4=NO\nTUNNEL_IPV6=NO\nTUNNEL_DNS=NO\n[statistics]\nDISABLE=YES\n[dns]\nUNIXPATH=$PT_UNUSED_SOURCE/missing\n[vpn]\nUNIXPATH=$PT_UNUSED_SOURCE/missing\n[cadet]\nUNIXPATH=$PT_UNUSED_SOURCE/missing\n[dht]\nUNIXPATH=$PT_UNUSED_SOURCE/missing\n")?;
    let config = directory.0.join("pt.conf");
    let configured = [OsStr::new("-c"), config.as_os_str()];
    let (status, _, stderr) = execute(
        &directory.0,
        &[
            configured[0],
            configured[1],
            OsStr::new("-L"),
            OsStr::new("DEBUG"),
        ],
    )?;
    if !status.success() || !stderr.contains("no useful service enabled") {
        return Err(format!("disabled native PT: {status}; {stderr}").into());
    }
    let (status, stdout, stderr) = execute(&directory.0, &[OsStr::new("--help")])?;
    if !status.success() || !stdout.contains("TUNNEL_IPV4") {
        return Err(format!("native PT help: {status}; {stderr}").into());
    }
    for arguments in [&["--unknown-pt-option"][..], &["unexpected-positional"][..]] {
        let mut request = configured.to_vec();
        request.extend(arguments.iter().map(OsStr::new));
        let (status, _, _) = execute(&directory.0, &request)?;
        if status.success() {
            return Err(format!("PT accepted invalid arguments: {arguments:?}").into());
        }
    }
    Ok(())
}
