//! Project metadata and version-pinned GNUnet installation path selection.
use crate::{
    Configuration, Environment, Error, Limits, ProcessEnvironment, bytes_path, path_bytes,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// Official `GNUNET_UTIL_VERSION` at the selected v0.29.1 source revision.
pub const UTIL_VERSION: u32 = 0x000a_0104;
/// Metadata of the selected normal official Meson build profile. These fields
/// describe preprocessor definitions, not implemented Rust feature coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildProfile {
    /// Whether GNUNET_EXPERIMENTAL is defined, which the pinned CLI tests with
    /// ifdef even when the configured value is zero.
    pub experimental_macro_defined: bool,
    /// Actual configured experimental value, separately retained as metadata.
    pub experimental_macro_value: bool,
}
/// v0.29.1 normal Meson `-Dexperimental=false`: defined to zero. Consequently
/// its `--is-experimental` presence test exits zero without certifying features.
pub const OFFICIAL_BUILD_PROFILE: BuildProfile = BuildProfile {
    experimental_macro_defined: true,
    experimental_macro_value: false,
};
/// Project metadata corresponding to all fields of `GNUNET_OS_ProjectData`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectData {
    /// Library basename used for Linux mapped-image discovery.
    pub libname: Option<Vec<u8>>,
    /// Directory name below share/lib/doc.
    pub project_dirname: Vec<u8>,
    /// Anchor binary searched in PATH.
    pub binary_name: Option<Vec<u8>>,
    /// Primary installation environment override.
    pub env_varname: Option<Vec<u8>>,
    /// Alternative override used only if the primary is absent.
    pub env_varname_alt: Option<Vec<u8>>,
    /// Default configuration directory environment override.
    pub base_config_varname: Option<Vec<u8>>,
    /// Bug-report address.
    pub bug_email: Vec<u8>,
    /// Project homepage.
    pub homepage: Vec<u8>,
    /// Filename below XDG_CONFIG_HOME or /etc.
    pub config_file: Vec<u8>,
    /// User filename when XDG_CONFIG_HOME is absent.
    pub user_config_file: Vec<u8>,
    /// Distribution version, separate from the Rust SDK package version.
    pub version: Vec<u8>,
    /// Whether this is a GNU project.
    pub is_gnu: bool,
    /// Optional gettext domain.
    pub gettext_domain: Option<Vec<u8>>,
    /// Explicit gettext directory, if supplied by the project.
    pub gettext_path: Option<PathBuf>,
    /// Source availability URL for the AGPL protocol owner.
    pub agpl_url: Option<Vec<u8>>,
}
impl Default for ProjectData {
    fn default() -> Self {
        Self {
            libname: Some(b"libgnunetutil".to_vec()),
            project_dirname: b"gnunet".to_vec(),
            binary_name: Some(b"gnunet-arm".to_vec()),
            env_varname: Some(b"GNUNET_PREFIX".to_vec()),
            env_varname_alt: None,
            base_config_varname: Some(b"GNUNET_BASE_CONFIG".to_vec()),
            bug_email: b"gnunet-developers@gnu.org".to_vec(),
            homepage: b"http://www.gnu.org/s/gnunet/".to_vec(),
            config_file: b"gnunet.conf".to_vec(),
            user_config_file: b"~/.config/gnunet.conf".to_vec(),
            version: b"0.29.1".to_vec(),
            is_gnu: true,
            gettext_domain: Some(b"gnunet".to_vec()),
            gettext_path: None,
            agpl_url: Some(b"https://git.gnunet.org/gnunet.git/tag/?h=v0.29.1".to_vec()),
        }
    }
}
impl ProjectData {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        for value in [
            &self.project_dirname,
            &self.bug_email,
            &self.homepage,
            &self.config_file,
            &self.user_config_file,
            &self.version,
        ]
        .into_iter()
        .map(Vec::as_slice)
        .chain(
            [
                &self.libname,
                &self.binary_name,
                &self.env_varname,
                &self.env_varname_alt,
                &self.base_config_varname,
                &self.gettext_domain,
                &self.agpl_url,
            ]
            .into_iter()
            .filter_map(|v| v.as_deref()),
        ) {
            if value.contains(&0) {
                return Err(Error::InvalidInput);
            }
        }
        if self
            .gettext_path
            .as_deref()
            .is_some_and(|path| path_bytes(path).map_or(true, |bytes| bytes.contains(&0)))
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Select an existing readable default entrypoint, using XDG, user file,
    /// /etc/config_file, then /etc/project/config_file. Does not load it.
    pub fn default_filename(
        &self,
        environment: &impl Environment,
    ) -> Result<Option<PathBuf>, Error> {
        self.default_filename_observed(environment, None)
    }
    /// Discover an entrypoint with borrowed synchronous diagnostics for the
    /// filename/file-test helper read points, without loading configuration.
    pub fn default_filename_observed(
        &self,
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Option<PathBuf>, Error> {
        self.validate()?;
        let candidate = match environment.variable(b"XDG_CONFIG_HOME") {
            Some(mut directory) => {
                directory.push(b'/');
                directory.extend_from_slice(&self.config_file);
                directory
            }
            None => self.user_config_file.clone(),
        };
        let mut global = b"/etc/".to_vec();
        global.extend_from_slice(&self.config_file);
        let mut project = b"/etc/".to_vec();
        project.extend_from_slice(&self.project_dirname);
        project.push(b'/');
        project.extend_from_slice(&self.config_file);
        let empty = Configuration::new(Limits::default());
        for candidate in [candidate, global, project] {
            let path = match empty.expand_filename_observed(&candidate, environment, observer) {
                Ok(path) => path,
                // Native filename expansion returns NULL without HOME; its
                // file_test_read then rejects this candidate and tries /etc.
                Err(Error::Missing) => continue,
                Err(error) => return Err(error),
            };
            if empty.file_test_observed(&path, true, observer) {
                return Ok(Some(bytes_path(&candidate)?));
            }
        }
        Ok(None)
    }
}
pub(crate) fn readable_directory(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_dir()) && accessible(path, true, true)
}
#[cfg(unix)]
fn accessible(path: &Path, read: bool, execute: bool) -> bool {
    use nix::unistd::{AccessFlags, access};
    let mut flags = AccessFlags::F_OK;
    if read {
        flags |= AccessFlags::R_OK;
    }
    if execute {
        flags |= AccessFlags::X_OK;
    }
    access(path, flags).is_ok()
}
#[cfg(not(unix))]
fn accessible(path: &Path, read: bool, execute: bool) -> bool {
    let _ = execute;
    if read {
        #[cfg(windows)]
        if path.is_dir() {
            return gnunet_native::paths::open_directory(path, true).is_ok();
        }
        fs::File::open(path).is_ok()
    } else {
        path.exists()
    }
}

/// The nine official installation path requests, in declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// Project prefix.
    Prefix,
    /// Public binary directory.
    Bindir,
    /// Project library/plugin directory.
    Libdir,
    /// Project data directory.
    Datadir,
    /// Translation catalogs.
    Localedir,
    /// Current executable's installation prefix.
    SelfPrefix,
    /// Icon directory.
    Icondir,
    /// Project documentation.
    Docdir,
    /// Project helper executables.
    Libexecdir,
}
impl PathKind {
    /// All path requests, including SELF_PREFIX.
    pub const ALL: [Self; 9] = [
        Self::Prefix,
        Self::Bindir,
        Self::Libdir,
        Self::Datadir,
        Self::Localedir,
        Self::SelfPrefix,
        Self::Icondir,
        Self::Docdir,
        Self::Libexecdir,
    ];
    pub(crate) const BOOTSTRAP: [(Self, &'static [u8]); 8] = [
        (Self::Datadir, b"DATADIR"),
        (Self::Libdir, b"LIBDIR"),
        (Self::Bindir, b"BINDIR"),
        (Self::Prefix, b"PREFIX"),
        (Self::Localedir, b"LOCALEDIR"),
        (Self::Icondir, b"ICONDIR"),
        (Self::Docdir, b"DOCDIR"),
        (Self::Libexecdir, b"LIBEXECDIR"),
    ];
    const fn index(self) -> usize {
        match self {
            Self::Prefix => 0,
            Self::Bindir => 1,
            Self::Libdir => 2,
            Self::Datadir => 3,
            Self::Localedir => 4,
            Self::SelfPrefix => 5,
            Self::Icondir => 6,
            Self::Docdir => 7,
            Self::Libexecdir => 8,
        }
    }
    pub(crate) const fn diagnostic_name(self) -> &'static str {
        // These two source switch fallthrough labels are observable v0.29.1 text.
        match self {
            Self::Prefix | Self::Localedir => "IPK_LOCALEDIR",
            Self::Bindir => "IPK_BINDIR",
            Self::Libdir => "IPK_LIBDIR",
            Self::Datadir => "IPK_DATADIR",
            Self::SelfPrefix => "IPK_SELF_PREFIX",
            Self::Icondir | Self::Docdir => "IPK_DOCDIR",
            Self::Libexecdir => "IPK_LIBEXECDIR",
        }
    }
}
/// Explicit installation discovery provenance; a fallback path is not proof
/// that a binary or directory exists or is safe to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationOrigin {
    /// Caller supplied an installation profile.
    Explicit,
    /// Project environment override (including an explicitly empty override).
    Environment,
    /// A project library mapped into this Linux process.
    MappedLibrary,
    /// Project anchor found through the exact C PATH search.
    SearchPath,
    /// Native current executable location.
    Executable,
    /// No installation could be discovered.
    Unavailable,
}
/// Resolved official path strings. No process-global environment is mutated.
#[derive(Clone, Debug)]
pub struct Installation {
    paths: [Option<PathBuf>; 9],
    origin: InstallationOrigin,
}
impl Installation {
    /// Empty explicit profile, useful for applications that intentionally have
    /// no installed defaults. Native discovery is separately named and fallible.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            paths: core::array::from_fn(|_| None),
            origin: InstallationOrigin::Explicit,
        }
    }
    /// Native discovery. Linux mapped-image/PATH/executable ordering follows C.
    /// A statically linked Rust program on Darwin has no GNUnet util dylib to
    /// discover; it uses the official executable/PATH fallbacks. An embedding
    /// with a distinct shared-library location supplies `from_locations`.
    pub fn discover(project: &ProjectData, environment: &impl Environment) -> Result<Self, Error> {
        project.validate()?;
        let executable = std::env::current_exe()
            .ok()
            .and_then(|p| executable_directory(project, &p));
        let primary = project
            .env_varname
            .as_deref()
            .and_then(|n| environment.variable(n));
        let override_value = primary.or_else(|| {
            project
                .env_varname_alt
                .as_deref()
                .and_then(|n| environment.variable(n))
        });
        let found = if let Some(value) = override_value {
            let location = bytes_path(&value)?;
            #[cfg(windows)]
            let location = if location.as_os_str().is_empty() {
                location
            } else {
                environment
                    .absolute_path(&location)
                    .map_err(|error| crate::io_error(&location, error))?
            };
            Some((location, InstallationOrigin::Environment))
        } else {
            #[cfg(target_os = "linux")]
            let mapped = mapped_library(project);
            #[cfg(not(target_os = "linux"))]
            let mapped = None;
            #[cfg(target_os = "macos")]
            let native_first = executable
                .clone()
                .map(|p| (p, InstallationOrigin::Executable));
            #[cfg(not(target_os = "macos"))]
            let native_first = None;
            mapped
                .map(|p| (p, InstallationOrigin::MappedLibrary))
                .or(native_first)
                .or_else(|| {
                    path_anchor(project, environment).map(|p| (p, InstallationOrigin::SearchPath))
                })
                .or_else(|| {
                    executable
                        .clone()
                        .map(|p| (p, InstallationOrigin::Executable))
                })
        };
        let Some((location, origin)) = found else {
            return Ok(Self {
                origin: InstallationOrigin::Unavailable,
                ..Self::empty()
            });
        };
        if path_bytes(&location)?.is_empty() {
            return Ok(Self {
                origin,
                ..Self::empty()
            });
        }
        let mut result = Self::from_locations(project, &location, executable.as_deref())?;
        result.origin = origin;
        Ok(result)
    }
    /// Resolve a project installation location and optionally distinct executable
    /// location, applying the actual bin/lib/lib32/lib64/multiarch rules.
    pub fn from_locations(
        project: &ProjectData,
        location: &Path,
        self_location: Option<&Path>,
    ) -> Result<Self, Error> {
        project.validate()?;
        let mut result = Self::empty();
        for kind in PathKind::ALL {
            result.paths[kind.index()] = shape(
                project,
                if kind == PathKind::SelfPrefix {
                    self_location.unwrap_or(location)
                } else {
                    location
                },
                kind,
            )?;
        }
        Ok(result)
    }
    /// Borrow a resolved path, retaining its trailing slash as in C.
    #[must_use]
    pub fn path(&self, kind: PathKind) -> Option<&Path> {
        self.paths[kind.index()].as_deref()
    }
    /// How the project location was found.
    #[must_use]
    pub const fn origin(&self) -> InstallationOrigin {
        self.origin
    }
}
fn executable_directory(project: &ProjectData, executable: &Path) -> Option<PathBuf> {
    let bytes = path_bytes(executable.parent()?).ok()?.to_vec();
    #[cfg(target_os = "linux")]
    {
        let _ = project;
        if bytes.len() < 4 || bytes[bytes.len() - 4] != b'/' {
            return None;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = project;
    bytes_path(&bytes).ok()
}
#[cfg(target_os = "linux")]
fn mapped_library(project: &ProjectData) -> Option<PathBuf> {
    use std::io::Read;
    let needle = project.libname.as_deref()?;
    if needle.is_empty() {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open("/proc/self/maps")
        .ok()?
        .take(4 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .ok()?;
    for line in bytes.split(|b| *b == b'\n') {
        let Some(path) = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|v| !v.is_empty())
            .nth(5)
        else {
            continue;
        };
        if let Some(index) = path.windows(needle.len()).position(|w| w == needle) {
            return bytes_path(&path[..index]).ok();
        }
    }
    None
}
#[cfg(not(windows))]
fn path_anchor(project: &ProjectData, environment: &impl Environment) -> Option<PathBuf> {
    let binary = project.binary_name.as_deref()?;
    let paths = environment.variable(b"PATH")?;
    for directory in paths.split(|b| *b == b':') {
        let mut candidate = directory.to_vec();
        candidate.push(b'/');
        candidate.extend_from_slice(binary);
        let candidate = bytes_path(&candidate).ok()?;
        if fs::metadata(&candidate).is_ok_and(|m| m.is_file())
            && accessible(&candidate, false, false)
        {
            return bytes_path(directory).ok();
        }
    }
    None
}
#[cfg(windows)]
fn path_anchor(project: &ProjectData, environment: &impl Environment) -> Option<PathBuf> {
    let binary = bytes_path(project.binary_name.as_deref()?).ok()?;
    let paths = bytes_path(&environment.variable(b"PATH")?).ok()?;
    for directory in std::env::split_paths(paths.as_os_str()) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            let Ok(directory) = environment.absolute_path(&directory) else {
                continue;
            };
            directory
        };
        let candidate = directory.join(&binary);
        let candidate = if candidate.extension().is_none() {
            candidate.with_extension("exe")
        } else {
            candidate
        };
        if fs::metadata(&candidate).is_ok_and(|m| m.is_file())
            && accessible(&candidate, false, true)
        {
            return Some(directory);
        }
    }
    None
}
#[cfg(windows)]
#[path = "project/windows.rs"]
mod windows;
#[cfg(windows)]
use windows::shape;
#[cfg(not(windows))]
fn shape(project: &ProjectData, location: &Path, kind: PathKind) -> Result<Option<PathBuf>, Error> {
    let mut root = path_bytes(location)?.to_vec();
    while root.len() > 1 && root.ends_with(b"/") {
        root.pop();
    }
    if root.is_empty() {
        return Ok(None);
    }
    let mut basedir = true;
    if root.len() > 6
        && (root[root.len() - 6..].eq_ignore_ascii_case(b"/lib32")
            || root[root.len() - 6..].eq_ignore_ascii_case(b"/lib64"))
    {
        if matches!(kind, PathKind::Libdir | PathKind::Libexecdir) {
            basedir = false;
        } else {
            root.truncate(root.len() - 6);
        }
    } else if root.len() > 4
        && (root[root.len() - 4..].eq_ignore_ascii_case(b"/bin")
            || root[root.len() - 4..].eq_ignore_ascii_case(b"/lib"))
    {
        root.truncate(root.len() - 4);
    }
    let mut multiarch = None;
    if let Some(index) = root.windows(5).position(|v| v == b"/lib/") {
        let suffix = &root[index + 5..];
        if !suffix.contains(&b'/') {
            multiarch = Some(suffix.to_vec());
            root.truncate(index);
        }
    }
    while root.len() > 1 && root.ends_with(b"/") {
        root.pop();
    }
    let mut project_suffix = b"/".to_vec();
    project_suffix.extend_from_slice(&project.project_dirname);
    project_suffix.push(b'/');
    let directory = match kind {
        PathKind::Prefix | PathKind::SelfPrefix => b"/".to_vec(),
        PathKind::Bindir => b"/bin/".to_vec(),
        PathKind::Datadir => {
            let mut p = b"/share".to_vec();
            p.extend_from_slice(&project_suffix);
            p
        }
        PathKind::Localedir => b"/share/locale/".to_vec(),
        PathKind::Icondir => b"/share/icons/".to_vec(),
        PathKind::Docdir => {
            let mut p = b"/share/doc".to_vec();
            p.extend_from_slice(&project_suffix);
            p
        }
        PathKind::Libdir | PathKind::Libexecdir => {
            if kind == PathKind::Libexecdir {
                project_suffix.extend_from_slice(b"libexec/");
            }
            if basedir {
                let mut candidates = Vec::new();
                let mut lib = if kind == PathKind::Libexecdir {
                    b"/lib/".to_vec()
                } else {
                    b"/lib".to_vec()
                };
                if let Some(multiarch) = &multiarch {
                    if kind != PathKind::Libexecdir {
                        lib.push(b'/');
                    }
                    lib.extend_from_slice(multiarch);
                }
                lib.extend_from_slice(&project_suffix);
                candidates.push(lib);
                if kind == PathKind::Libdir {
                    let mut relative = b"/lib".to_vec();
                    relative.extend_from_slice(&project_suffix);
                    candidates.push(relative);
                }
                let mut arch = if cfg!(target_pointer_width = "64") {
                    b"/lib64".to_vec()
                } else {
                    b"/lib32".to_vec()
                };
                arch.extend_from_slice(&project_suffix);
                candidates.push(arch);
                for candidate in candidates {
                    let mut path = root.clone();
                    path.extend_from_slice(&candidate);
                    if readable_directory(&bytes_path(&path)?) {
                        return Ok(Some(bytes_path(&path)?));
                    }
                }
            }
            project_suffix
        }
    };
    root.extend_from_slice(&directory);
    Ok(Some(bytes_path(&root)?))
}

/// Explicit cache owner for C's first-use SUID/libexec path behavior. A fresh
/// cache is useful for an independently scoped embedding or isolated tests.
#[derive(Default)]
pub struct BinaryPathCache {
    pub(crate) suid: Option<Vec<u8>>,
    pub(crate) libexec: Option<PathBuf>,
}
impl BinaryPathCache {
    /// Start with neither first-use path cached.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProjectData {
    /// Resolve the official libexec binary path with the process-first-use cache.
    /// This uses the project's installation context without SUID_BINARY_PATH.
    /// Absolute program paths bypass discovery and the shared cache.
    pub fn libexec_binary_path(&self, program: &[u8]) -> Result<PathBuf, Error> {
        let mut cache = global_binary_cache()
            .lock()
            .map_err(|_| Error::InvalidValue)?;
        self.libexec_binary_path_with(program, &ProcessEnvironment, &mut cache)
    }

    /// Resolve using an explicit environment and independently owned cache.
    /// Sharing this cache retains the first successful libexec discovery across
    /// projects/calls, including Configuration's SUID fallback using this cache.
    /// A fresh cache is a fresh process-like embedding context; no program runs.
    pub fn libexec_binary_path_with(
        &self,
        program: &[u8],
        environment: &impl Environment,
        cache: &mut BinaryPathCache,
    ) -> Result<PathBuf, Error> {
        if program.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if let Some(path) = crate::explicit_program_path(program, environment)? {
            return Ok(path);
        }
        self.validate()?;
        if cache.libexec.is_none() {
            cache.libexec = Installation::discover(self, environment)?
                .path(PathKind::Libexecdir)
                .map(Path::to_path_buf);
        }
        let Some(directory) = cache.libexec.as_deref() else {
            return bytes_path(program);
        };
        let mut full = path_bytes(directory)?.to_vec();
        full.try_reserve(program.len())
            .map_err(|_| Error::Capacity)?;
        full.extend_from_slice(program);
        bytes_path(&full)
    }
}

pub(crate) fn global_binary_cache() -> &'static Mutex<BinaryPathCache> {
    static CACHE: OnceLock<Mutex<BinaryPathCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BinaryPathCache::new()))
}
/// Native default entrypoint discovery using the current read-only environment.
pub fn default_filename(project: &ProjectData) -> Result<Option<PathBuf>, Error> {
    project.default_filename(&ProcessEnvironment)
}
