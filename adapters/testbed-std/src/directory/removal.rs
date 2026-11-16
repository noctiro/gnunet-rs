//! Bounded explicit removal through held original directory objects.
use super::*;
use filesystem::EntryInfo;
fn record(first: &mut Option<Failure>, error: Failure) {
    if let Some(first) = first {
        first.add(error.cause);
        first.cleanup_count = first.cleanup_count.saturating_add(error.cleanup_count);
    } else {
        *first = Some(error);
    }
}
fn contents(
    directory: &NativeDirectory,
    path: &Path,
    remaining: &mut usize,
    depth: usize,
    limits: Limits,
) -> Result<(), Failure> {
    if depth > limits.cleanup_depth {
        return Err(Fault::Capacity.into());
    }
    let entries = directory
        .entries()
        .map_err(|error| Failure::io("enumerate original cleanup directory", path, error))?;
    let mut failure = None;
    for name in entries {
        if *remaining == 0 {
            record(&mut failure, Fault::Capacity.into());
            break;
        }
        *remaining -= 1;
        let name = match name {
            Ok(name) => name,
            Err(error) => {
                record(
                    &mut failure,
                    Failure::io("read original cleanup entry", path, error),
                );
                continue;
            }
        };
        if depth == 0
            && [MARK, LOCK, COUNTER]
                .iter()
                .any(|control| name == OsStr::new(control))
        {
            continue;
        }
        let selected = path.join(&name);
        if path_bytes(&selected) > limits.path_bytes {
            record(&mut failure, Fault::TooLarge.into());
            continue;
        }
        let result = (|| match directory
            .entry_info(&name)
            .map_err(|error| Failure::io("inspect original cleanup entry", &selected, error))?
        {
            EntryInfo::File(info) => {
                let file = directory
                    .open_file_for_sync(&name)
                    .map_err(|error| Failure::io("open original cleanup file", &selected, error))?;
                let remove = (|| {
                    if FileIdentity::of(&file)? != info.identity {
                        return Err(io::Error::other("cleanup file changed"));
                    }
                    directory.remove_file(&name, &file)
                })();
                let close = filesystem::close(file);
                match (remove, close) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(error), close) => {
                        let mut failure =
                            Failure::io("remove original cleanup file", &selected, error);
                        if let Err(error) = close {
                            failure.add(Cause::Io {
                                operation: "close cleanup file",
                                path: selected.clone(),
                                error,
                            });
                        }
                        Err(failure)
                    }
                    (Ok(()), Err(error)) => {
                        Err(Failure::io("close removed cleanup file", &selected, error))
                    }
                }
            }
            EntryInfo::Directory(info) => {
                let child = directory.open_directory(&name).map_err(|error| {
                    Failure::io("open original cleanup child", &selected, error)
                })?;
                if FileIdentity::of(child.as_file())
                    .map_err(|error| Failure::io("cleanup child identity", &selected, error))?
                    != info.identity
                {
                    return Err(Cause::Changed.into());
                }
                let inner = contents(&child, &selected, remaining, depth + 1, limits);
                let remove = directory.remove_directory(&name, &child).map_err(|error| {
                    Failure::io("remove original cleanup child", &selected, error)
                });
                match (inner, remove) {
                    (Ok(()), result) => result,
                    (Err(mut first), result) => {
                        if let Err(error) = result {
                            first.add(error.cause);
                        }
                        Err(first)
                    }
                }
            }
            EntryInfo::Other => directory
                .remove_special(&name)
                .map_err(|error| Failure::io("remove original special entry", &selected, error)),
        })();
        if let Err(error) = result {
            record(&mut failure, error);
        }
    }
    failure.map_or(Ok(()), Err)
}
impl Directory {
    pub fn remove(self, remove_paths: bool) -> Result<Removal, Failure> {
        if !remove_paths {
            return Ok(Removal::Kept(self.path));
        }
        self.check_identity()
            .map_err(|error| Failure::io("qualify original removal root", &self.path, error))?;
        // The caller has stopped every external user of this private tree.
        // Enumeration and unlinking remain relative to the original even if
        // its public parent path moves; symlink targets are never traversed.
        let mut remaining = self.limits.cleanup_entries;
        contents(&self.original, &self.path, &mut remaining, 0, self.limits)?;
        let counter_path = self.path.join(COUNTER);
        let counter = self
            .original
            .open_file_for_sync(OsStr::new(COUNTER))
            .map_err(|error| Failure::io("open final cleanup counter", &counter_path, error))?;
        let remove = self.original.remove_file(OsStr::new(COUNTER), &counter);
        let close = filesystem::close(counter);
        match (remove, close) {
            (Ok(()), Ok(())) => {}
            (Err(error), close) => {
                let mut failure = Failure::io("remove final cleanup counter", &counter_path, error);
                if let Err(error) = close {
                    failure.add(Cause::Io {
                        operation: "close final cleanup counter",
                        path: counter_path,
                        error,
                    });
                }
                return Err(failure);
            }
            (Ok(()), Err(error)) => {
                return Err(Failure::io("close removed counter", counter_path, error));
            }
        }
        self.original
            .remove_file(OsStr::new(LOCK), &self.lock)
            .map_err(|error| Failure::io("remove original lock link", &self.path, error))?;
        self.original
            .remove_file(OsStr::new(MARK), &self.marker)
            .map_err(|error| Failure::io("remove original marker link", &self.path, error))?;
        self.parent
            .remove_directory(&self.name, &self.original)
            .map_err(|error| Failure::io("remove original root", &self.path, error))?;
        self.parent
            .sync()
            .map_err(|error| Failure::io("sync removed root parent", &self.path, error))?;
        Ok(Removal::Removed(self.path))
    }
}
