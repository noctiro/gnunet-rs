//! Native Windows installation components, retaining drive and UNC roots.
use super::*;

pub(super) fn shape(
    project: &ProjectData,
    location: &Path,
    kind: PathKind,
) -> Result<Option<PathBuf>, Error> {
    if location.as_os_str().is_empty() {
        return Ok(None);
    }
    let mut root = location.to_owned();
    let leaf = root.file_name().and_then(|n| n.to_str());
    let architecture_lib =
        leaf.is_some_and(|n| n.eq_ignore_ascii_case("lib32") || n.eq_ignore_ascii_case("lib64"));
    let mut basedir = true;
    if architecture_lib && matches!(kind, PathKind::Libdir | PathKind::Libexecdir) {
        basedir = false;
    } else if architecture_lib
        || leaf.is_some_and(|n| n.eq_ignore_ascii_case("bin") || n.eq_ignore_ascii_case("lib"))
    {
        root.pop();
    }
    let mut multiarch = None;
    if root
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|n| n.eq_ignore_ascii_case("lib"))
    {
        multiarch = root.file_name().map(|n| n.to_owned());
        root.pop();
        root.pop();
    }
    let project = bytes_path(&project.project_dirname)?;
    // Project directory is a suffix, never a new drive or rooted namespace.
    if project.has_root()
        || matches!(
            project.components().next(),
            Some(std::path::Component::Prefix(_))
        )
    {
        return Err(Error::InvalidInput);
    }
    let relative = match kind {
        PathKind::Prefix | PathKind::SelfPrefix => PathBuf::new(),
        PathKind::Bindir => "bin".into(),
        PathKind::Datadir => Path::new("share").join(&project),
        PathKind::Localedir => PathBuf::from("share").join("locale"),
        PathKind::Icondir => PathBuf::from("share").join("icons"),
        PathKind::Docdir => PathBuf::from("share").join("doc").join(&project),
        PathKind::Libdir | PathKind::Libexecdir => {
            let suffix = if kind == PathKind::Libexecdir {
                project.join("libexec")
            } else {
                project
            };
            if basedir {
                let mut lib = PathBuf::from("lib");
                if let Some(arch) = &multiarch {
                    lib.push(arch);
                }
                for candidate in [
                    lib.join(&suffix),
                    Path::new("lib").join(&suffix),
                    Path::new(if cfg!(target_pointer_width = "64") {
                        "lib64"
                    } else {
                        "lib32"
                    })
                    .join(&suffix),
                ] {
                    let candidate = root.join(candidate);
                    if readable_directory(&candidate) {
                        return Ok(Some(trailing(candidate)));
                    }
                }
            }
            suffix
        }
    };
    Ok(Some(trailing(root.join(relative))))
}
fn trailing(mut path: PathBuf) -> PathBuf {
    path.push("");
    path
}
