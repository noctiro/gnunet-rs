//! Same-original-parent publication and independent native barrier observations.
use super::*;
use filesystem::publication::{self, Destination};
impl Directory {
    pub fn publish(
        &mut self,
        target: &Path,
        body: &[u8],
        replace: Replace,
        expected: Option<&NativeDirectory>,
    ) -> Result<Published, Failure> {
        self.check()?;
        let target =
            absolute(target).map_err(|error| Failure::io("resolve publication", target, error))?;
        if path_bytes(&target) > self.limits.path_bytes {
            return Err(Fault::TooLarge.into());
        }
        let (parent_path, name) =
            split(&target).map_err(|error| Failure::io("split publication", &target, error))?;
        let parent = NativeDirectory::open(parent_path)
            .map_err(|error| Failure::io("open publication parent", parent_path, error))?;
        let identity = FileIdentity::of(parent.as_file())
            .map_err(|error| Failure::io("publication parent identity", parent_path, error))?;
        if let Some(expected) = expected
            && FileIdentity::of(expected.as_file())
                .map_err(|error| Failure::io("canonical home identity", parent_path, error))?
                != identity
        {
            return Err(Cause::Changed.into());
        }
        let verify = || {
            self.check_identity()?;
            if FileIdentity::of(NativeDirectory::open(parent_path)?.as_file())? != identity {
                return Err(io::Error::other(
                    "original TESTBED publication parent changed",
                ));
            }
            Ok(())
        };
        let result = publication::publish(
            &parent,
            name,
            body,
            match replace {
                Replace::NewOnly => Destination::Create,
                Replace::Allowed => Destination::Replace,
            },
            verify,
        );
        match result {
            Err(error) => {
                let exposure = if error.may_have_published {
                    self.fenced = true;
                    Exposure::Uncertain
                } else if matches!(error.cleanup, publication::Cleanup::NotNeeded) {
                    Exposure::Unchanged
                } else {
                    Exposure::Staged
                };
                let mut failure = Failure::from(Cause::Publication {
                    path: target,
                    error: Box::new(error),
                });
                failure.exposure = exposure;
                Err(failure)
            }
            Ok(published) => {
                let (file, directory_sync) = published.into_parts();
                let observed = verify();
                let close = filesystem::close(file);
                let mut failure = observed
                    .err()
                    .map(|error| Failure::io("recheck installed publication", &target, error));
                if let Err(error) = close {
                    if let Some(failure) = &mut failure {
                        failure.add(Cause::Io {
                            operation: "close published lease",
                            path: target.clone(),
                            error,
                        });
                    } else {
                        failure = Some(Failure::io("close published lease", &target, error));
                    }
                }
                if let Some(mut failure) = failure {
                    self.fenced = true;
                    failure.exposure = Exposure::Installed;
                    return Err(failure);
                }
                Ok(Published {
                    path: target,
                    bytes: body.len(),
                    directory_sync,
                })
            }
        }
    }
}
