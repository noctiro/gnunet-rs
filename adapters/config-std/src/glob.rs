//! Pinned GNUnet DISK_glob semantics, not a POSIX shell glob implementation.
use crate::diagnostic::{Argument as A, BorrowedObserver, Diagnostic, Level, Site};
use crate::{Configuration, Error, bytes_path, io_error, path_bytes};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn matches(pattern: &[u8], name: &[u8]) -> bool {
    // Keep the original glob_match backtracking, including the trailing-star
    // boundary behavior. Only '*' is special; '?' and backslash are literal.
    let (mut text, mut pat) = (0usize, 0usize);
    let mut backtrack = None;
    loop {
        if pattern.get(pat) == Some(&b'*') {
            backtrack = Some((text, pat));
            pat += 1;
        } else if pattern.get(pat) == name.get(text) {
            if pat == pattern.len() {
                return true;
            }
            text += 1;
            pat += 1;
        } else {
            let Some((saved_text, saved_pat)) = backtrack else {
                return false;
            };
            text = saved_text + 1;
            if text >= name.len() {
                return false;
            }
            pat = saved_pat;
        }
    }
}

pub(crate) fn matching_files(
    cfg: &Configuration,
    observer: Option<BorrowedObserver<'_>>,
    pattern: &Path,
    maximum: usize,
    maximum_scan: usize,
) -> Result<Vec<PathBuf>, Error> {
    let bytes = path_bytes(pattern)?;
    if bytes.iter().any(|b| matches!(b, b'+' | b'[' | b'~')) {
        cfg.emit_to(
            observer,
            Diagnostic {
                level: Level::ERROR,
                component: Some(b"util-disk"),
                site: Site {
                    id: "config.glob.unsupported",
                    file: b"disk.c",
                    function: b"GNUNET_DISK_glob",
                    line: 1077,
                },
                domain: None,
                template: b"unsupported glob pattern: '%s'\n",
                arguments: &[A::Bytes(bytes)],
            },
        );
        return Err(Error::InvalidInput);
    }
    let slash = bytes
        .iter()
        .rposition(|b| *b == b'/')
        .ok_or(Error::InvalidInput)?;
    if bytes[..slash].contains(&b'*') {
        cfg.report_break(
            observer,
            Site {
                id: "config.glob.parent-star-break",
                file: b"disk.c",
                function: b"GNUNET_DISK_glob",
                line: 1094,
            },
        );
        cfg.emit_to(
            observer,
            Diagnostic {
                level: Level::ERROR,
                component: Some(b"util-disk"),
                site: Site {
                    id: "config.glob.parent-star",
                    file: b"disk.c",
                    function: b"GNUNET_DISK_glob",
                    line: 1096,
                },
                domain: None,
                template: b"glob pattern may only contain '*' in the final path component\n",
                arguments: &[],
            },
        );
        return Err(Error::InvalidInput);
    }
    let directory = if slash == 0 {
        std::env::current_dir().map_err(|e| io_error(".", e))?
    } else {
        bytes_path(&bytes[..slash])?
    };
    let pattern = &bytes[slash + 1..];
    cfg.emit_to(
        observer,
        Diagnostic {
            level: Level::DEBUG,
            component: Some(b"util-disk"),
            site: Site {
                id: "config.glob.scanning",
                file: b"disk.c",
                function: b"GNUNET_DISK_glob",
                line: 1110,
            },
            domain: None,
            template: b"scanning directory '%s' for glob matches on '%s'\n",
            arguments: &[A::Bytes(path_bytes(&directory)?), A::Bytes(pattern)],
        },
    );
    let entries = fs::read_dir(&directory).map_err(|error| {
        cfg.syscall(
            observer,
            Some(b"util-disk"),
            Site {
                id: "config.disk.opendir",
                file: b"disk.c",
                function: b"GNUNET_DISK_directory_scan",
                line: 906,
            },
            Level::WARNING,
            b"opendir",
            &directory,
            &error,
        );
        io_error(&directory, error)
    })?;
    let mut paths = Vec::new();
    for (scanned, entry) in entries.enumerate() {
        if scanned >= maximum_scan {
            return Err(Error::Capacity);
        }
        let entry = entry.map_err(|e| io_error(&directory, e))?;
        let name = entry.file_name();
        let name = path_bytes(Path::new(&name))?;
        cfg.emit_to(
            observer,
            Diagnostic {
                level: Level::DEBUG,
                component: Some(b"util-disk"),
                site: Site {
                    id: "config.glob.checking",
                    file: b"disk.c",
                    function: b"glob_cb",
                    line: 1044,
                },
                domain: None,
                template: b"checking glob '%s' against '%s'\n",
                arguments: &[A::Bytes(pattern), A::Bytes(name)],
            },
        );
        if matches(pattern, name) {
            cfg.emit_to(
                observer,
                Diagnostic {
                    level: Level::DEBUG,
                    component: Some(b"util-disk"),
                    site: Site {
                        id: "config.glob.found",
                        file: b"disk.c",
                        function: b"glob_cb",
                        line: 1052,
                    },
                    domain: None,
                    template: b"found glob match '%s'\n",
                    arguments: &[A::Bytes(path_bytes(&entry.path())?)],
                },
            );
            if paths.len() >= maximum {
                return Err(Error::Capacity);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::matches;
    #[test]
    fn actual_c_wildcard_boundaries() {
        assert!(matches(b"*.conf", b"a.conf"));
        assert!(matches(b"*.conf", b".conf"));
        assert!(matches(b"*.conf", b".hidden.conf"));
        assert!(!matches(b"*", b"anything"));
        assert!(matches(b"*", b""));
        assert!(matches(b"a*", b"a"));
        assert!(!matches(b"a*", b"ab"));
        assert!(!matches(b"?.conf", b"a.conf"));
        assert!(matches(b"?.conf", b"?.conf"));
    }
}
