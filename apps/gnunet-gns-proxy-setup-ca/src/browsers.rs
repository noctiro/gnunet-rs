//! Optional NSS platform adapter. Only the generated public certificate enters NSS.
use crate::{Cause, budget::Budget, files::PublicFile, output::Output};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::Duration,
};

#[derive(Debug)]
struct CommandFailure {
    arguments: Vec<OsString>,
    original: Cause,
    kill: Option<io::Error>,
    reaped: Option<ExitStatus>,
    wait: Option<io::Error>,
}
impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS helper {:?}: {}; cleanup kill={:?}, reaped={:?}, wait={:?}",
            self.arguments, self.original, self.kill, self.reaped, self.wait
        )
    }
}
impl Error for CommandFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn command(
    arguments: &[OsString],
    input: Option<File>,
    budget: &Budget,
    verbose: bool,
) -> Result<Option<ExitStatus>, Cause> {
    budget.check()?;
    let mut command = Command::new("certutil");
    command
        .args(arguments)
        .stdin(input.map_or_else(Stdio::null, Stdio::from))
        .stdout(Stdio::null())
        .stderr(if verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let result = (|| -> Result<ExitStatus, Cause> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            budget.check()?;
            thread::sleep(Duration::from_millis(10));
        }
    })();
    match result {
        Ok(status) => Ok(Some(status)),
        Err(original) => {
            // Retire this exact subprocess even when time/logging failed.
            let kill = child.kill().err();
            let (reaped, wait) = match child.wait() {
                Ok(status) => (Some(status), None),
                Err(error) => (None, Some(error)),
            };
            Err(Box::new(CommandFailure {
                arguments: arguments.to_vec(),
                original,
                kill,
                reaped,
                wait,
            }))
        }
    }
}
pub(super) fn probe(budget: &Budget, output: &mut Output) -> Result<(), Cause> {
    output.status(format_args!(
        "CA provider: rcgen 0.14.10 with AWS-LC; OpenSSL/GnuTLS binaries are not required"
    ))?;
    match command(&[OsString::from("-H")], None, budget, output.verbose)? {
        Some(status) => output.status(format_args!(
            "Optional NSS certutil help probe returned {status}; no CA or browser trust was changed"
        ))?,
        None => output.status(format_args!(
            "Optional NSS certutil is unavailable; browser import would be skipped"
        ))?,
    }
    Ok(())
}
fn directory(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn discover(budget: &Budget) -> Result<Vec<PathBuf>, Cause> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(Vec::new());
    };
    let home = PathBuf::from(home);
    let mut profiles = Vec::new();
    let mut scanned = 0usize;
    for browser in ["firefox", "icecat"] {
        budget.check()?;
        let root = home.join(".mozilla").join(browser);
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            budget.check()?;
            scanned = scanned.checked_add(1).ok_or("NSS profile scan overflow")?;
            if scanned > 4096 {
                return Err("NSS profile scan capacity reached".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let bytes = name.as_bytes();
            if bytes.starts_with(b".") || !bytes.contains(&b'.') {
                continue;
            }
            let path = entry.path();
            if directory(&path)? {
                push(&mut profiles, path)?;
            }
        }
    }
    let chrome = home.join(".pki/nssdb");
    if directory(&chrome)? {
        push(&mut profiles, chrome)?;
    }
    profiles.sort();
    profiles.dedup();
    Ok(profiles)
}
fn push(profiles: &mut Vec<PathBuf>, path: PathBuf) -> Result<(), Cause> {
    if profiles.len() == 128 || path.as_os_str().as_bytes().len() > 4096 {
        return Err("NSS profile capacity reached".into());
    }
    profiles.try_reserve(1)?;
    profiles.push(path);
    Ok(())
}
fn database(path: &Path) -> io::Result<OsString> {
    match fs::metadata(path.join("cert9.db")) {
        Ok(_) => {
            let mut database = OsString::from("sql:");
            database.push(path);
            Ok(database)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path.as_os_str().to_owned()),
        Err(error) => Err(error),
    }
}
#[derive(Debug)]
struct NssStatusFailure {
    profile: PathBuf,
    target: PathBuf,
    status: ExitStatus,
}
impl fmt::Display for NssStatusFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS certutil import into {} failed with {}; generated CA remains at {}",
            self.profile.display(),
            self.status,
            self.target.display()
        )
    }
}
impl Error for NssStatusFailure {}
#[derive(Debug)]
struct ImportFailure {
    original: Option<Cause>,
    cleanup: Option<io::Error>,
}
impl fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS public-certificate import: original={:?}, public staging cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for ImportFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.as_ref().map(|error| error as _))
    }
}
pub(super) fn import(
    target: &Path,
    certificate: &str,
    budget: &Budget,
    output: &mut Output,
) -> Result<(), Cause> {
    let profiles = discover(budget)?;
    if profiles.is_empty() {
        output.status(format_args!(
            "No supported Firefox/Icecat or ~/.pki/nssdb profiles found; browser import skipped"
        ))?;
        return Ok(());
    }
    let mut public = PublicFile::new(target, certificate, budget)?;
    let result = (|| -> Result<(), Cause> {
        for profile in profiles {
            budget.check()?;
            let database = database(&profile)?;
            let lookup = [
                OsString::from("-L"),
                OsString::from("-n"),
                OsString::from("GNS Proxy CA"),
                OsString::from("-d"),
                database.clone(),
            ];
            match command(&lookup, None, budget, output.verbose)? {
                None => {
                    output.status(format_args!(
                        "NSS certutil is unavailable; remaining browser imports skipped"
                    ))?;
                    break;
                }
                Some(status) if status.success() => {
                    return Err(format!(
                        "existing NSS nickname GNS Proxy CA preserved in {}; browser trust installation requires an explicit operator decision; generated CA remains at {}",
                        profile.display(), target.display()
                    ).into());
                }
                Some(_) => {}
            }
            budget.check()?;
            let arguments = [
                OsString::from("-A"),
                OsString::from("-n"),
                OsString::from("GNS Proxy CA"),
                OsString::from("-t"),
                OsString::from("CT,,"),
                OsString::from("-d"),
                database,
            ];
            match command(&arguments, Some(public.input()?), budget, output.verbose)? {
                Some(status) if status.success() => output.status(format_args!(
                    "Imported public GNS Proxy CA into {}",
                    profile.display()
                ))?,
                Some(status) => {
                    return Err(Box::new(NssStatusFailure {
                        profile,
                        target: target.to_owned(),
                        status,
                    }));
                }
                None => return Err(
                    "NSS certutil disappeared before import; no successful trust import claimed"
                        .into(),
                ),
            }
        }
        Ok(())
    })();
    let cleanup = public.finish().err();
    match (result, cleanup) {
        (Ok(()), None) => Ok(()),
        (original, cleanup) => Err(Box::new(ImportFailure {
            original: original.err(),
            cleanup,
        })),
    }
}
