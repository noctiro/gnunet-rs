//! Optional NSS imports retain original native profile and child owners.
use crate::{Cause, budget::Budget, files::PublicFile, output::Output};
use std::{
    error::Error,
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
    process::ExitStatus,
};
mod command;
mod profiles;
pub(super) use command::Helper;
pub(super) async fn probe(
    helper: &Helper,
    budget: &Budget,
    output: &mut Output,
) -> Result<(), Cause> {
    output.status(format_args!(
        "CA provider: rcgen 0.14.10 with AWS-LC; OpenSSL/GnuTLS binaries are not required"
    ))?;
    match helper
        .run(&[OsString::from("-H")], None, budget, output.verbose)
        .await?
    {
        Some(status) => output.status(format_args!(
            "Optional NSS certutil help probe returned {status}; no CA or browser trust was changed"
        ))?,
        None => output.status(format_args!(
            "Optional NSS certutil is unavailable; browser import would be skipped"
        ))?,
    }
    Ok(())
}
#[derive(Debug)]
struct NssStatusFailure {
    profile: PathBuf,
    target: PathBuf,
    status: ExitStatus,
    observation: Option<io::Error>,
}
impl fmt::Display for NssStatusFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS certutil import into {}: exit={}, profile observation={:?}; generated CA remains at {}",
            self.profile.display(),
            self.status,
            self.observation,
            self.target.display()
        )
    }
}
impl Error for NssStatusFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.observation.as_ref().map(|error| error as _)
    }
}
#[derive(Debug)]
struct ImportFailure {
    original: Option<Cause>,
    cleanup: Option<Cause>,
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
        self.original.as_deref().or(self.cleanup.as_deref())
    }
}
pub(super) async fn import(
    helper: &Helper,
    target: &Path,
    certificate: &str,
    budget: &Budget,
    output: &mut Output,
) -> Result<(), Cause> {
    let profiles = profiles::discover(helper.database.as_deref(), budget).await?;
    if profiles.is_empty() {
        output.status(format_args!(
            "No supported NSS database profiles found; browser import skipped"
        ))?;
        return Ok(());
    }
    let mut public = PublicFile::new(target, certificate, budget).await?;
    let result = async {
        for profile in profiles {
            budget.check().await?;
            let database = profile.database()?;
            let lookup = [
                OsString::from("-L"),
                OsString::from("-n"),
                OsString::from("GNS Proxy CA"),
                OsString::from("-d"),
                database.clone(),
            ];
            match helper.run(&lookup, None, budget, output.verbose).await? {
                None => {
                    output.status(format_args!(
                        "NSS certutil is unavailable; remaining browser imports skipped"
                    ))?;
                    break;
                }
                Some(status) if status.success() => {
                    return Err(format!(
                        "existing NSS nickname GNS Proxy CA preserved in {}; browser trust installation requires an explicit operator decision; generated CA remains at {}",
                        profile.path.display(), target.display()
                    ).into());
                }
                Some(_) => {}
            }
            profile.check()?;
            budget.check().await?;
            let arguments = [
                OsString::from("-A"),
                OsString::from("-n"),
                OsString::from("GNS Proxy CA"),
                OsString::from("-t"),
                OsString::from("CT,,"),
                OsString::from("-d"),
                database,
            ];
            let imported = helper.run(&arguments, Some(public.input()?), budget, output.verbose).await?;
            let observation = profile.check().err();
            match imported {
                Some(status) if status.success() && observation.is_none() => output.status(format_args!(
                    "Imported public GNS Proxy CA into {}",
                    profile.path.display()
                ))?,
                Some(status) => {
                    return Err(Box::new(NssStatusFailure {
                        profile: profile.path,
                        target: target.to_owned(),
                        status,
                        observation,
                    }) as Cause);
                }
                None => return Err(
                    "NSS certutil disappeared before import; no successful trust import claimed"
                        .into(),
                ),
            }
        }
        Ok(())
    }.await;
    let cleanup = public.finish().err();
    match (result, cleanup) {
        (Ok(()), None) => Ok(()),
        (original, cleanup) => Err(Box::new(ImportFailure {
            original: original.err(),
            cleanup,
        })),
    }
}
