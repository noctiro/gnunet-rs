//! Shared dollar expansion with explicit native filename contexts.
use crate::diagnostic::{Argument as A, Level};
use crate::{Configuration, Error, bytes_path, path_bytes};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Caller-selected process environment. Tests and supervisors can provide an
/// isolated snapshot without mutating global process environment variables.
pub trait Environment {
    /// Look up an exact environment name, retaining non-UTF-8 bytes on Unix.
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>>;
    /// Current working directory for relative filenames.
    fn current_dir(&self) -> io::Result<PathBuf>;
    /// Resolve a native filename without opening it. The default uses only this
    /// context's current directory. On Windows, a relative path on another drive
    /// needs an explicit override; it never consults ambient per-drive state.
    fn absolute_path(&self, path: &Path) -> io::Result<PathBuf> {
        if path.is_absolute() {
            return Ok(path.to_owned());
        }
        let cwd = self.current_dir()?;
        #[cfg(windows)]
        {
            use std::path::{Component, Prefix};
            if !cwd.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot current directory is not absolute",
                ));
            }
            if let Some(Component::Prefix(prefix)) = path.components().next() {
                let Prefix::Disk(drive) = prefix.kind() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid relative Windows prefix",
                    ));
                };
                let same_drive = matches!(cwd.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(d) | Prefix::VerbatimDisk(d) if d.eq_ignore_ascii_case(&drive)));
                if !same_drive {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "snapshot has no current directory for the requested drive",
                    ));
                }
                let tail = path
                    .strip_prefix(prefix.as_os_str())
                    .map_err(io::Error::other)?;
                return Ok(cwd.join(tail));
            }
        }
        Ok(cwd.join(path))
    }
    /// Explicit home directory. The default reads HOME from this context only.
    /// A process provider can query its native profile when HOME is unavailable.
    fn home_dir(&self) -> io::Result<Option<PathBuf>> {
        self.variable(b"HOME")
            .map(|value| {
                bytes_path(&value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .transpose()
    }
}

/// Read-only access to the host's current environment and working directory.
pub struct ProcessEnvironment;
impl Environment for ProcessEnvironment {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        if name.contains(&0) || name.contains(&b'=') {
            return None;
        }
        let name = bytes_path(name).ok()?;
        let value = std::env::var_os(name.as_os_str())?;
        path_bytes(std::path::Path::new(&value))
            .ok()
            .map(<[u8]>::to_vec)
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        std::env::current_dir()
    }
    fn absolute_path(&self, path: &Path) -> io::Result<PathBuf> {
        // std implements GetFullPathNameW on Windows, including per-drive cwd.
        // Empty official filenames denote the current directory, not an error.
        if path.as_os_str().is_empty() {
            return self.current_dir();
        }
        std::path::absolute(path)
    }
    #[cfg(windows)]
    fn home_dir(&self) -> io::Result<Option<PathBuf>> {
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return Ok(Some(home.into()));
        }
        gnunet_native::paths::profile_directory().map(Some)
    }
}

#[cfg(windows)]
mod windows;

struct Expansion<'a, 'observer, E> {
    observer: Option<crate::diagnostic::BorrowedObserver<'observer>>,
    cfg: &'a Configuration,
    environment: &'a E,
    active: Vec<(Vec<u8>, bool)>,
    operations: usize,
    depth: usize,
}
impl<E: Environment> Expansion<'_, '_, E> {
    fn all(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if input.len() > self.cfg.limits.max_expanded_bytes {
            return Err(Error::Capacity);
        }
        let mut output = input.to_vec();
        let mut cursor = 0;
        while cursor < output.len() {
            if output[cursor] == b'$' {
                self.operations = self.operations.checked_add(1).ok_or(Error::Capacity)?;
                if self.operations > self.cfg.limits.max_expansions {
                    return Err(Error::Capacity);
                }
                let replacement = self.leading(&output[cursor..])?;
                let size = cursor
                    .checked_add(replacement.len())
                    .ok_or(Error::Capacity)?;
                if size > self.cfg.limits.max_expanded_bytes {
                    return Err(Error::Capacity);
                }
                output.truncate(cursor);
                output.extend_from_slice(&replacement);
            }
            cursor += 1;
        }
        Ok(output)
    }
    fn leading(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.depth += 1;
        if self.depth > self.cfg.limits.max_expansion_depth {
            self.cfg.note_to(
                self.observer,
                "config.dollar.depth",
                Level::WARNING,
                b"expand_dollar",
                2721,
                b"Recursive expansion suspected, aborting $-expansion for term `%s'\n",
                &[A::Bytes(input)],
            );
            self.depth -= 1;
            return Err(Error::Cycle);
        }
        let result = self.leading_inner(input);
        self.depth -= 1;
        result
    }
    fn leading_inner(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.cfg.note_to(
            self.observer,
            "config.dollar.asked",
            Level::DEBUG,
            b"expand_dollar",
            2726,
            b"Asked to $-expand %s\n",
            &[A::Bytes(input)],
        );
        if !input.starts_with(b"$") {
            self.cfg.note_to(
                self.observer,
                "config.dollar.not-leading",
                Level::DEBUG,
                b"expand_dollar",
                2730,
                b"Doesn't start with $ - not expanding\n",
                &[],
            );
            return Ok(input.to_vec());
        }
        if self.active.len() >= self.cfg.limits.max_expansion_depth {
            return Err(Error::Cycle);
        }
        let (name, default, separator, suffix) = if input.get(1) == Some(&b'{') {
            let mut depth = 1usize;
            let mut end = 2;
            while end < input.len() {
                match input[end] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                end += 1;
            }
            if depth != 0 {
                self.cfg.note_to(
                    self.observer,
                    "config.dollar.missing-brace",
                    Level::WARNING,
                    b"expand_dollar",
                    2756,
                    b"Missing closing `}' in option `%s'\n",
                    &[A::Bytes(input)],
                );
                return Ok(input.to_vec());
            }
            let expression = &input[2..end];
            let (name, default) = if let Some(colon) = expression.iter().position(|b| *b == b':') {
                let mut default = &expression[colon + 1..];
                if default.first().is_some_and(|b| matches!(b, b'-' | b'=')) {
                    default = &default[1..];
                }
                (&expression[..colon], Some(default))
            } else {
                (expression, None)
            };
            (name, default, None, &input[end + 1..])
        } else {
            let end = input
                .iter()
                .position(|b| matches!(b, b'/' | b'\\' | b' '))
                .unwrap_or(input.len());
            (
                &input[1..end],
                None,
                input.get(end).copied(),
                input.get(end + 1..).unwrap_or_default(),
            )
        };
        self.cfg.note_to(
            self.observer,
            "config.dollar.split",
            Level::DEBUG,
            b"expand_dollar",
            2805,
            b"Split into `%s' and `%s' with default %s\n",
            &[
                A::Bytes(name),
                A::Bytes(suffix),
                default.map_or(A::NullString, A::Bytes),
            ],
        );
        let paths = self.cfg.get_observed(b"PATHS", name, self.observer);
        let from_paths = paths.is_some();
        let prefix = paths
            .map(<[u8]>::to_vec)
            .or_else(|| self.environment.variable(name));
        let prefix = match prefix {
            Some(prefix) => prefix,
            None => match default {
                Some(default) => self.leading(default)?,
                None => {
                    self.cfg.note_to(self.observer,"config.dollar.missing",Level::WARNING,b"expand_dollar",2828,b"Failed to expand `%s' in `%s' as it is neither found in [PATHS] nor defined as an environmental variable\n",&[A::Bytes(name),A::Bytes(input)]);
                    return Ok(input.to_vec());
                }
            },
        };
        if self.active.iter().any(|(active, was_paths)| {
            *was_paths == from_paths
                && if from_paths {
                    self.cfg.case_equals(active, name)
                } else {
                    active == name
                }
        }) {
            return Err(Error::Cycle);
        }
        self.active.push((name.to_vec(), from_paths));
        let expanded = self.all(&prefix);
        self.active.pop();
        let mut expanded = expanded?;
        let size = expanded
            .len()
            .checked_add(usize::from(separator.is_some()))
            .and_then(|n| n.checked_add(suffix.len()))
            .ok_or(Error::Capacity)?;
        if size > self.cfg.limits.max_expanded_bytes {
            return Err(Error::Capacity);
        }
        if let Some(separator) = separator {
            expanded.push(separator);
        }
        expanded.extend_from_slice(suffix);
        Ok(expanded)
    }
}

impl Configuration {
    /// Expand every dollar expression using `[PATHS]` before the environment.
    /// Missing variables and unmatched braces stay literal, as in the C helper.
    /// Defaults use `${NAME:-value}` (also `${NAME:=value}` or `${NAME:value}`).
    /// Recursive references/resource exhaustion return an explicit error rather
    /// than repeating the C helper's unbounded recursion.
    pub fn expand_dollar(
        &self,
        input: &[u8],
        environment: &impl Environment,
    ) -> Result<Vec<u8>, Error> {
        self.expand_dollar_observed(input, environment, None)
    }
    /// Dollar/PATHS recursion with the same local diagnostic route throughout.
    pub fn expand_dollar_observed(
        &self,
        input: &[u8],
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Expansion {
            observer,
            cfg: self,
            environment,
            active: Vec::new(),
            operations: 0,
            depth: 0,
        }
        .all(input)
    }
    /// Apply official filename expansion to raw bytes. Absolute paths are
    /// retained; '~' uses HOME (including the C helper's '~user' behavior);
    /// other relative paths use the environment's current working directory.
    pub fn expand_filename(
        &self,
        input: &[u8],
        environment: &impl Environment,
    ) -> Result<PathBuf, Error> {
        self.expand_filename_observed(input, environment, None)
    }
    /// Filename expansion with a borrowed synchronous observer, replacing
    /// persistent observation for this call without retaining the callback.
    pub fn expand_filename_observed(
        &self,
        input: &[u8],
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<PathBuf, Error> {
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if input.len() > self.limits.max_expanded_bytes {
            return Err(Error::Capacity);
        }
        #[cfg(windows)]
        {
            windows::filename(self, input, environment, observer)
        }
        #[cfg(not(windows))]
        self.expand_unix_filename(input, environment, observer)
    }
    #[cfg(not(windows))]
    fn expand_unix_filename(
        &self,
        input: &[u8],
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<PathBuf, Error> {
        if input.starts_with(b"/") {
            return bytes_path(input);
        }
        let (mut base, relative) = if input.starts_with(b"~") {
            let Some(home) = environment.variable(b"HOME") else {
                return Err(self.missing_home(observer));
            };
            let suffix = &input[1..];
            (home, suffix.strip_prefix(b"/").unwrap_or(suffix))
        } else {
            let cwd = match environment.current_dir() {
                Ok(path) => path_bytes(&path)?.to_vec(),
                Err(error) => {
                    self.emit_to(
                        observer,
                        crate::diagnostic::Diagnostic {
                            level: Level::WARNING,
                            component: Some(b"util-strings"),
                            site: crate::diagnostic::Site {
                                id: "config.filename.getcwd",
                                file: b"strings.c",
                                function: b"GNUNET_STRINGS_filename_expand",
                                line: 589,
                            },
                            domain: Some(b"gnunet"),
                            template: b"`%s' failed at %s:%d with error: %s\n",
                            arguments: &[
                                A::Bytes(b"getcwd"),
                                A::Bytes(b"strings.c"),
                                A::Signed(589),
                                A::Error(&error),
                            ],
                        },
                    );
                    environment
                        .variable(b"PWD")
                        .unwrap_or_else(|| b"./".to_vec())
                }
            };
            (cwd, input)
        };
        if !base.ends_with(b"/") {
            base.push(b'/');
        }
        base.extend_from_slice(relative);
        if base.len() > self.limits.max_expanded_bytes {
            return Err(Error::Capacity);
        }
        bytes_path(&base)
    }
    fn missing_home(&self, observer: Option<crate::diagnostic::BorrowedObserver<'_>>) -> Error {
        self.emit_to(
            observer,
            crate::diagnostic::Diagnostic {
                level: Level::WARNING,
                component: Some(b"util-strings"),
                site: crate::diagnostic::Site {
                    id: "config.filename.home-missing",
                    file: b"strings.c",
                    function: b"GNUNET_STRINGS_filename_expand",
                    line: 550,
                },
                domain: Some(b"gnunet"),
                template: b"Failed to expand `$HOME': environment variable `HOME' not set",
                arguments: &[],
            },
        );
        Error::Missing
    }
    /// Resolve a setting as an official filename through dollar then filename
    /// expansion. Non-UTF-8 values are preserved on Unix.
    pub fn get_filename(
        &self,
        section: &[u8],
        key: &[u8],
        environment: &impl Environment,
    ) -> Result<PathBuf, Error> {
        self.get_filename_observed(section, key, environment, None)
    }
    /// Filename lookup, recursive dollar and host expansion through one local
    /// observer; no callback is retained in the returned owned path.
    pub fn get_filename_observed(
        &self,
        section: &[u8],
        key: &[u8],
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<PathBuf, Error> {
        let Some(value) = self.get_observed(section, key, observer) else {
            self.note_to(
                observer,
                "config.filename.missing",
                Level::DEBUG,
                b"GNUNET_CONFIGURATION_get_value_filename",
                2895,
                b"Failed to retrieve filename\n",
                &[],
            );
            return Err(Error::Missing);
        };
        self.expand_filename_observed(
            &self.expand_dollar_observed(value, environment, observer)?,
            environment,
            observer,
        )
    }
    /// Host convenience for a UTF-8 section/key and the process environment.
    pub fn get_path(&self, section: &str, key: &str) -> Result<PathBuf, Error> {
        self.get_filename(section.as_bytes(), key.as_bytes(), &ProcessEnvironment)
    }
}
