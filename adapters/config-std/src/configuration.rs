//! Ordered official configuration state and filesystem loading.
use crate::diagnostic::{Argument as A, Diagnostic, Level, Site};
use crate::{
    BinaryPathCache, CaseContext, CaseSnapshot, Environment, Error, Installation, PathKind,
    ProcessEnvironment, ProjectData, bytes_path, glob, io_error, path_bytes, values,
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Explicit resource limits for host-controlled configuration inputs.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bytes in an individual file or deserialize buffer.
    pub max_input_bytes: usize,
    /// Sum of file/buffer bytes consumed by one load operation.
    pub max_loaded_bytes: usize,
    /// File load attempts per operation and retained provenance entries overall.
    pub max_files: usize,
    /// Active include ancestry depth.
    pub max_include_depth: usize,
    /// Global distinct sections, including inaccessible secret sections.
    pub max_sections: usize,
    /// Global distinct keys, including deleted-value tombstones.
    pub max_entries: usize,
    /// Bytes in one name or value.
    pub max_value_bytes: usize,
    /// Diagnostic definitions retained across all entries.
    pub max_definitions: usize,
    /// Matches in one include glob.
    pub max_glob_matches: usize,
    /// Directory entries inspected by one include glob.
    pub max_glob_scan_entries: usize,
    /// Bytes after dollar/filename expansion or serialization.
    pub max_expanded_bytes: usize,
    /// Recursive dollar reference depth.
    pub max_expansion_depth: usize,
    /// Dollar substitutions considered by one expansion operation.
    pub max_expansions: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 4 * 1024 * 1024,
            max_loaded_bytes: 32 * 1024 * 1024,
            max_files: 1024,
            max_include_depth: 128,
            max_sections: 4096,
            max_entries: 65536,
            max_value_bytes: 1024 * 1024,
            max_definitions: 131072,
            max_glob_matches: 4096,
            max_glob_scan_entries: 65536,
            max_expanded_bytes: 32 * 1024 * 1024,
            max_expansion_depth: 128,
            max_expansions: 65536,
        }
    }
}

/// Official dirty indication. As in the pinned C implementation, setting a
/// value alone does not change this flag; section removal and writes do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dirty {
    /// No section removal or failed write since construction/successful write.
    Clean,
    /// Removing a section removed at least one stored entry.
    Modified,
    /// The last write failed.
    WriteFailed,
}

/// Complete outcome of the C directory-loader operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryLoad {
    /// Directory entries inspected, including skipped non-configuration files.
    pub entries_seen: usize,
    /// Successfully parsed `.conf` entries.
    pub files_loaded: usize,
}
impl DirectoryLoad {
    /// Pinned C return: an entirely empty directory is NO (0); a directory
    /// containing only ignored files is OK (1), just like one with loaded files.
    #[must_use]
    pub const fn c_status(self) -> i32 {
        if self.entries_seen == 0 { 0 } else { 1 }
    }
}

/// One removed physical definition, reported only after successful publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanRemoval {
    /// Original section spelling.
    pub section: Vec<u8>,
    /// Original option spelling.
    pub option: Vec<u8>,
    /// One-based physical line removed.
    pub line: usize,
}

/// A physical source definition, in highest-precedence-first entry order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Definition {
    /// Original normalized value, before later overrides.
    pub value: Vec<u8>,
    /// Expanded source filename, or `<input>` for memory-only input.
    pub filename: PathBuf,
    /// One-based physical line number.
    pub line: usize,
}

/// One ordered configuration key. A removed value leaves the original key slot.
#[derive(Clone, Debug)]
pub struct Entry {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    sources: Vec<Definition>,
}
impl Entry {
    /// First-inserted spelling of this case-insensitive key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    /// Current committed bytes; `None` is a removed-value tombstone.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
    /// Every recorded physical definition, highest precedence first.
    #[must_use]
    pub fn definitions(&self) -> &[Definition] {
        &self.sources
    }
}

/// One section in newest-created-first official list order.
#[derive(Clone, Debug)]
pub struct Section {
    name: Vec<u8>,
    entries: Vec<Entry>,
    inaccessible: bool,
    secret_file: Option<PathBuf>,
    secret_origin: Option<(PathBuf, usize)>,
    secret_stat: Option<Vec<u8>>,
}
impl Section {
    /// First-inserted section spelling.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Keys in newest-created-first order, including removed-value tombstones.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Whether any referenced secret source was inaccessible.
    #[must_use]
    pub const fn inaccessible(&self) -> bool {
        self.inaccessible
    }
}

/// One attempted configuration file load, in physical load order.
#[derive(Clone, Debug)]
pub struct FileSource {
    /// Filename used for loading.
    pub filename: PathBuf,
    /// Include nesting level, zero for a public top-level parse.
    pub level: usize,
    /// Requested secret section, if this entry represents INLINE-SECRET.
    pub restrict_section: Option<Vec<u8>>,
    /// The secret source could not be accessed or parsed.
    pub inaccessible: bool,
    contents: Option<Vec<u8>>,
}

/// Ordered host configuration implementing the official text/typed APIs.
pub struct Configuration {
    pub(crate) limits: Limits,
    sections: Vec<Section>,
    files: Vec<FileSource>,
    diagnostics: bool,
    definitions: usize,
    dirty: Dirty,
    main_filename: Option<PathBuf>,
    project: Arc<ProjectData>,
    case_context: CaseContext,
    installation: Installation,
    native_installation: bool,
    bootstrap: bool,
    observer: Option<crate::diagnostic::Observer>,
    load_called: bool,
}

struct Load<'observer> {
    observer: Option<crate::diagnostic::BorrowedObserver<'observer>>,
    stack: Vec<PathBuf>,
    bytes: usize,
    files: usize,
}
impl<'observer> Load<'observer> {
    fn observed(observer: Option<crate::diagnostic::BorrowedObserver<'observer>>) -> Self {
        Self {
            observer,
            stack: Vec::new(),
            bytes: 0,
            files: 0,
        }
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}
impl Configuration {
    /// Create an empty configuration with caller-selected finite bounds. Official
    /// installation PATHS can be inserted with [`Self::set_value`]. This does
    /// not infer a C installation prefix or load private configuration defaults.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self::new_in(limits, CaseContext::c())
    }
    /// Empty configuration sharing an explicit replaceable locale context. The
    /// constructor does no native locale IO. Locale replacement affects existing
    /// names/values in place; no keys are rehashed, merged or reordered.
    #[must_use]
    pub fn new_in(limits: Limits, case_context: CaseContext) -> Self {
        Self {
            limits,
            sections: Vec::new(),
            files: Vec::new(),
            diagnostics: false,
            definitions: 0,
            dirty: Dirty::Clean,
            main_filename: None,
            project: Arc::new(ProjectData::default()),
            case_context,
            installation: Installation::empty(),
            native_installation: false,
            bootstrap: false,
            observer: None,
            load_called: false,
        }
    }
    /// Shared explicit locale authority, retained by duplicates/secret children.
    /// Native process/thread locale changes outside this context are not tracked.
    #[must_use]
    pub fn case_context(&self) -> CaseContext {
        self.case_context.clone()
    }
    /// Attach an existing configuration to a caller-owned locale selection. This
    /// does not rewrite names, merge entries or change the previous context used
    /// by unrelated configurations. Attach a common context before duplication to
    /// model one C caller's shared locale across all those live configurations.
    pub fn set_case_context(&mut self, context: CaseContext) {
        self.case_context = context;
    }
    pub(crate) fn case_equals(&self, first: &[u8], second: &[u8]) -> bool {
        self.case_context.snapshot().equals(first, second)
    }
    /// Install/retire an explicit source-diagnostic observer. No diagnostic,
    /// filesystem access or logger side effect is synthesized by installation.
    /// Fresh/duplicate handles retain this shared observer authority.
    pub fn observe(
        &mut self,
        observer: Option<crate::diagnostic::Observer>,
    ) -> Option<crate::diagnostic::Observer> {
        std::mem::replace(&mut self.observer, observer)
    }
    pub(crate) fn report_break(
        &self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        site: Site,
    ) {
        self.emit_to(
            observer,
            Diagnostic {
                level: Level::ERROR,
                component: None,
                site,
                domain: Some(b"gnunet"),
                template: b"Assertion failed at %s:%d.\n",
                arguments: &[A::Bytes(site.file), A::Signed(i64::from(site.line))],
            },
        );
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Source syscall, logical site and scoped observer are independent inputs"
    )]
    pub(crate) fn syscall(
        &self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        component: Option<&'static [u8]>,
        site: Site,
        level: Level,
        operation: &[u8],
        path: &Path,
        error: &std::io::Error,
    ) {
        self.emit_to(
            observer,
            Diagnostic {
                level,
                component,
                site,
                domain: Some(b"gnunet"),
                template: b"`%s' failed on file `%s' at %s:%d with error: %s\n",
                arguments: &[
                    A::Bytes(operation),
                    A::Bytes(path.as_os_str().as_encoded_bytes()),
                    A::Bytes(site.file),
                    A::Signed(i64::from(site.line)),
                    A::Error(error),
                ],
            },
        );
    }
    pub(crate) fn emit_to(
        &self,
        local: Option<crate::diagnostic::BorrowedObserver<'_>>,
        event: Diagnostic<'_>,
    ) {
        if let Some(observer) = local {
            observer(event);
        } else if let Some(observer) = &self.observer {
            observer(event);
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Operation observer and source format operands remain separate"
    )]
    pub(crate) fn note_to(
        &self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        id: &'static str,
        level: Level,
        function: &'static [u8],
        line: u32,
        template: &'static [u8],
        arguments: &[A<'_>],
    ) {
        self.emit_to(
            observer,
            Diagnostic {
                level,
                component: Some(b"util"),
                site: Site {
                    id,
                    file: b"configuration.c",
                    function,
                    line,
                },
                domain: None,
                template,
                arguments,
            },
        );
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Source error and scoped observer retain independent borrowed inputs"
    )]
    fn syntax_report(
        &self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        source: Option<&Path>,
        line: usize,
        id: &'static str,
        site_line: u32,
        template: &'static [u8],
        arguments: &[A<'_>],
    ) -> Error {
        self.note_to(
            observer,
            id,
            Level::WARNING,
            b"GNUNET_CONFIGURATION_deserialize",
            site_line,
            template,
            arguments,
        );
        Self::syntax(source, line)
    }
    /// Official configuration creation: retain project data and insert the
    /// eight available installation PATHS in the C API's insertion order.
    pub fn create(project: Arc<ProjectData>, limits: Limits) -> Result<Self, Error> {
        let installation = Installation::discover(&project, &ProcessEnvironment)?;
        let mut result = Self::with_installation(project, installation, limits)?;
        result.native_installation = true;
        Ok(result)
    }
    /// Create using an explicit, fully resolved installation context. This is
    /// useful to embedded hosts and deterministic isolated installations.
    pub fn with_installation(
        project: Arc<ProjectData>,
        installation: Installation,
        limits: Limits,
    ) -> Result<Self, Error> {
        project.validate()?;
        let mut result = Self {
            project,
            installation,
            bootstrap: true,
            ..Self::new(limits)
        };
        for (kind, key) in PathKind::BOOTSTRAP {
            if let Some(path) = result.installation.path(kind) {
                let value = path_bytes(path)?.to_vec();
                result.set_value(b"PATHS", key, Some(&value))?;
            }
        }
        Ok(result)
    }
    /// The immutable project data retained by this original configuration.
    #[must_use]
    pub fn project_data(&self) -> &ProjectData {
        &self.project
    }
    fn installation_now(&self) -> Result<Installation, Error> {
        if self.native_installation {
            Installation::discover(&self.project, &ProcessEnvironment)
        } else {
            Ok(self.installation.clone())
        }
    }
    pub(crate) fn fresh(&self) -> Result<Self, Error> {
        let mut result = if self.native_installation {
            Self::create(Arc::clone(&self.project), self.limits)
        } else if self.bootstrap {
            Self::with_installation(
                Arc::clone(&self.project),
                self.installation.clone(),
                self.limits,
            )
        } else {
            Ok(Self {
                project: Arc::clone(&self.project),
                installation: self.installation.clone(),
                ..Self::new(self.limits)
            })
        }?;
        result.observer = self.observer.clone();
        result.case_context = self.case_context.clone();
        Ok(result)
    }
    /// Retain physical source definitions and successfully parsed file contents
    /// for diagnostics and conditional duplicate-line cleanup.
    pub fn enable_diagnostics(&mut self) {
        self.diagnostics = true;
    }
    pub(crate) const fn diagnostics_enabled(&self) -> bool {
        self.diagnostics
    }
    /// Current values from a case-insensitively selected section, in official
    /// list order. Removed-value tombstones never produce an item.
    pub fn section_values<'a>(
        &'a self,
        section: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8], &'a [u8])> {
        self.section_values_observed(section, None)
    }
    /// Source section iterator with an explicitly borrowed diagnostic route.
    /// The returned iterator retains that borrow until exhausted/dropped; the
    /// configuration itself remains Send+Sync and stores no local callback.
    pub fn section_values_observed<'a>(
        &'a self,
        section: &'a [u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'a>>,
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8], &'a [u8])> {
        let selected = self
            .sections
            .iter()
            .find(|s| self.case_equals(&s.name, section));
        let mut entries = selected.map(|s| s.entries.iter());
        let mut finished = false;
        std::iter::from_fn(move || {
            if finished {
                return None;
            }
            let selected = selected?;
            for entry in entries.as_mut()? {
                if let Some(value) = &entry.value {
                    return Some((
                        selected.name.as_slice(),
                        entry.key.as_slice(),
                        value.as_slice(),
                    ));
                }
            }
            finished = true;
            if selected.inaccessible {
                self.note_to(observer,"config.iterate.inaccessible",Level::WARNING,b"GNUNET_CONFIGURATION_iterate_section_values",2193,b"Section '%s' is marked as inaccessible, because a configuration file that contains the section can't be read.\n",&[A::Bytes(section)]);
            }
            None
        })
    }
    /// Current dirty indication; file parsing preserves its previous value.
    #[must_use]
    pub const fn dirty(&self) -> Dirty {
        self.dirty
    }
    /// File load provenance in load order.
    #[must_use]
    pub fn loaded_files(&self) -> &[FileSource] {
        &self.files
    }
    /// Visible sections, retaining official list order.
    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|s| !s.inaccessible || !s.entries.is_empty())
    }
    /// All current values in official section/key list order.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8], &[u8], &[u8])> {
        self.sections.iter().flat_map(|section| {
            section.entries.iter().filter_map(move |entry| {
                entry
                    .value
                    .as_deref()
                    .map(|value| (section.name.as_slice(), entry.key.as_slice(), value))
            })
        })
    }
    fn section_index(&self, name: &[u8]) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| self.case_equals(&s.name, name))
    }
    fn entry_index(&self, section: &[u8], key: &[u8]) -> Option<(usize, usize)> {
        let section = self.section_index(section)?;
        Some((
            section,
            self.sections[section]
                .entries
                .iter()
                .position(|entry| self.case_equals(&entry.key, key))?,
        ))
    }
    /// Find an entry, including a removed-value tombstone and its provenance.
    #[must_use]
    pub fn entry(&self, section: &[u8], key: &[u8]) -> Option<&Entry> {
        self.entry_observed(section, key, None)
    }
    /// Lookup with immediate inaccessible-section diagnostics on the supplied
    /// local route, without storing it or changing returned entry ownership.
    #[must_use]
    pub fn entry_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Option<&Entry> {
        let section_index = self.section_index(section)?;
        let position = self.sections[section_index]
            .entries
            .iter()
            .position(|v| self.case_equals(&v.key, key));
        if position.is_none() && self.sections[section_index].inaccessible {
            self.note_to(observer,"config.find-entry.inaccessible",Level::WARNING,b"find_entry",738,b"Section '%s' is marked as inaccessible, because the configuration file that contains the section can't be read.  Attempts to use option '%s' will fail.\n",&[A::Bytes(section),A::Bytes(key)]);
        }
        position.map(|index| &self.sections[section_index].entries[index])
    }
    /// Read raw bytes without expansion; missing/deleted values return `None`.
    #[must_use]
    pub fn get(&self, section: &[u8], key: &[u8]) -> Option<&[u8]> {
        self.get_observed(section, key, None)
    }
    /// Raw lookup through a synchronous local diagnostic route.
    #[must_use]
    pub fn get_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Option<&[u8]> {
        self.entry_observed(section, key, observer)?
            .value
            .as_deref()
    }
    /// Whether a current value exists, including an empty string.
    #[must_use]
    pub fn have_value(&self, section: &[u8], key: &[u8]) -> bool {
        self.get(section, key).is_some()
    }
    fn checked_string(&self, input: &[u8]) -> Result<(), Error> {
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if input.len() > self.limits.max_value_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn ensure_section(&mut self, section: &[u8]) -> Result<usize, Error> {
        if let Some(index) = self.section_index(section) {
            return Ok(index);
        }
        self.checked_string(section)?;
        if self.sections.len() >= self.limits.max_sections {
            return Err(Error::Capacity);
        }
        self.sections.insert(
            0,
            Section {
                name: section.to_vec(),
                entries: Vec::new(),
                inaccessible: false,
                secret_file: None,
                secret_origin: None,
                secret_stat: None,
            },
        );
        Ok(0)
    }
    /// Set raw bytes or remove a value with `None`. Case-insensitive replacement
    /// preserves the first key/section spelling and list position. A new key is
    /// inserted at its section's front. Refusal changes no configuration state.
    pub fn set_value(
        &mut self,
        section: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.set_value_observed(section, key, value, None)
    }
    /// Source setter lookup diagnostics are synchronous, including adding an
    /// unknown key to a section previously marked inaccessible.
    pub fn set_value_observed(
        &mut self,
        section: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.checked_string(section)?;
        self.checked_string(key)?;
        if let Some(value) = value {
            self.checked_string(value)?;
        }
        if let Some((s, e)) = self.entry_index(section, key) {
            self.sections[s].entries[e].value = value.map(<[u8]>::to_vec);
            return Ok(());
        }
        let _previous_entry = self.entry_observed(section, key, observer);
        if self.sections.iter().map(|s| s.entries.len()).sum::<usize>() >= self.limits.max_entries {
            return Err(Error::Capacity);
        }
        if self.section_index(section).is_none() && self.sections.len() >= self.limits.max_sections
        {
            return Err(Error::Capacity);
        }
        let section = self.ensure_section(section)?;
        self.sections[section].entries.insert(
            0,
            Entry {
                key: key.to_vec(),
                value: value.map(<[u8]>::to_vec),
                sources: Vec::new(),
            },
        );
        Ok(())
    }
    /// Set an unsigned decimal setting.
    pub fn set_number(&mut self, section: &[u8], key: &[u8], value: u64) -> Result<(), Error> {
        self.set_number_observed(section, key, value, None)
    }
    /// Numeric setter through a local source diagnostic route.
    pub fn set_number_observed(
        &mut self,
        section: &[u8],
        key: &[u8],
        value: u64,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.set_value_observed(section, key, Some(value.to_string().as_bytes()), observer)
    }
    /// Set a C-locale float using the upstream six fractional digits.
    pub fn set_float(&mut self, section: &[u8], key: &[u8], value: f32) -> Result<(), Error> {
        self.set_float_observed(section, key, value, None)
    }
    /// Float setter through the same local lookup diagnostic route.
    pub fn set_float_observed(
        &mut self,
        section: &[u8],
        key: &[u8],
        value: f32,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        if let CaseSnapshot::CurrentThread(locale) = self.case_context.snapshot() {
            let formatted = locale
                .format_configuration_float(value)
                .map_err(values::native_value_error)?;
            return self.set_value_observed(section, key, Some(&formatted), observer);
        }
        let formatted = if value.is_nan() {
            if value.is_sign_negative() {
                "-nan".to_owned()
            } else {
                "nan".to_owned()
            }
        } else {
            format!("{value:.6}")
        };
        self.set_value_observed(section, key, Some(formatted.as_bytes()), observer)
    }
    /// Remove a whole section, including inaccessible metadata and tombstones.
    pub fn remove_section(&mut self, name: &[u8]) -> bool {
        let Some(index) = self.section_index(name) else {
            return false;
        };
        let section = self.sections.remove(index);
        if !section.entries.is_empty() {
            self.dirty = Dirty::Modified;
        }
        self.definitions -= section
            .entries
            .iter()
            .map(|e| e.sources.len())
            .sum::<usize>();
        true
    }
    /// Decimal unsigned configuration value.
    pub fn get_number(&self, section: &[u8], key: &[u8]) -> Result<u64, Error> {
        self.get_number_observed(section, key, None)
    }
    /// Same typed conversion with a local source-lookup diagnostic route.
    pub fn get_number_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<u64, Error> {
        values::parse_number_in(
            self.get_observed(section, key, observer)
                .ok_or(Error::Missing)?,
            &self.case_context.snapshot(),
        )
    }
    /// C-locale float, including hexadecimal, inf and NaN forms.
    pub fn get_float(&self, section: &[u8], key: &[u8]) -> Result<f32, Error> {
        self.get_float_observed(section, key, None)
    }
    /// Same typed conversion with a local source-lookup diagnostic route.
    pub fn get_float_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<f32, Error> {
        values::parse_float(
            self.get_observed(section, key, observer)
                .ok_or(Error::Missing)?,
            &self.case_context.snapshot(),
        )
    }
    /// Official fancy-size conversion, in bytes.
    pub fn get_size(&self, section: &[u8], key: &[u8]) -> Result<u64, Error> {
        self.get_size_observed(section, key, None)
    }
    /// Same typed conversion with a local source-lookup diagnostic route.
    pub fn get_size_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<u64, Error> {
        values::parse_size_in(
            self.get_observed(section, key, observer)
                .ok_or(Error::Missing)?,
            &self.case_context.snapshot(),
        )
    }
    /// Official relative time conversion, in microseconds.
    pub fn get_time(&self, section: &[u8], key: &[u8]) -> Result<u64, Error> {
        self.get_time_observed(section, key, None)
    }
    /// Local-observed time conversion. Malformed input is a safe Rust error;
    /// the undefined C malformed-relative path is never executed as an oracle.
    pub fn get_time_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<u64, Error> {
        let result = values::parse_relative_time_in(
            self.get_observed(section, key, observer)
                .ok_or(Error::Missing)?,
            &self.case_context.snapshot(),
        );
        if result.is_err() {
            // The source's malformed relative parser has an uninitialized read.
            // This is a safe Rust error observation, never C-execution evidence.
            self.emit_to(observer, Diagnostic {
                level: Level::ERROR,
                component: None,
                site: Site {
                    id: "common.config.invalid",
                    file: b"common_logging.c",
                    function: b"GNUNET_log_config_invalid",
                    line: 1534,
                },
                domain: Some(b"gnunet"),
                template:
                    b"Configuration specifies invalid value for option `%s' in section `%s': %s\n",
                arguments: &[
                    A::Bytes(key),
                    A::Bytes(section),
                    A::Translated {
                        domain: b"gnunet",
                        message: b"Not a valid relative time specification",
                    },
                ],
            });
        }
        result
    }
    /// Match a choice case-insensitively and return the caller's canonical bytes.
    pub fn get_choice<'a>(
        &self,
        section: &[u8],
        key: &[u8],
        choices: &[&'a [u8]],
    ) -> Result<&'a [u8], Error> {
        self.get_choice_observed(section, key, choices, None)
    }
    /// Same canonical choice lookup with local inaccessible/invalid diagnostics.
    pub fn get_choice_observed<'a>(
        &self,
        section: &[u8],
        key: &[u8],
        choices: &[&'a [u8]],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<&'a [u8], Error> {
        let value = self
            .get_observed(section, key, observer)
            .ok_or(Error::Missing)?;
        let choice = choices.iter().find(|c| self.case_equals(c, value)).copied();
        if let Some(choice) = choice {
            return Ok(choice);
        }
        self.emit_to(observer, Diagnostic {
            level: Level::ERROR,
            component: Some(b"util"),
            site: Site { id: "config.choice.invalid", file: b"configuration.c", function: b"GNUNET_CONFIGURATION_get_value_choice", line: 2621 },
            domain: Some(b"gnunet"),
            template: b"Configuration value '%s' for '%s' in section '%s' is not in set of legal choices\n",
            arguments: &[A::Bytes(value), A::Bytes(key), A::Bytes(section)],
        });
        Err(Error::InvalidValue)
    }
    /// Only YES or NO, case-insensitive, are official boolean settings.
    pub fn get_yesno(&self, section: &[u8], key: &[u8]) -> Result<bool, Error> {
        self.get_yesno_observed(section, key, None)
    }
    /// Boolean choice with a local source diagnostic route.
    pub fn get_yesno_observed(
        &self,
        section: &[u8],
        key: &[u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<bool, Error> {
        Ok(self.get_choice_observed(section, key, &[b"YES", b"NO"], observer)? == b"YES")
    }
    /// Decode the official Crockford byte-string setting into the exact output
    /// size. As in C, unknown characters/size mismatch fail and low padding bits
    /// are not required to be zero.
    pub fn get_data(&self, section: &[u8], key: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.get_data_observed(section, key, output, None)
    }
    /// Fixed-size data lookup with a local source diagnostic route.
    pub fn get_data_observed(
        &self,
        section: &[u8],
        key: &[u8],
        output: &mut [u8],
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        values::decode_data(
            self.get_observed(section, key, observer)
                .ok_or(Error::Missing)?,
            output,
        )
    }

    /// Parse a memory buffer. Includes require a real source filename. Accepted
    /// earlier lines remain applied after a later syntax/include error, as in C.
    pub fn deserialize(&mut self, input: &[u8], source: Option<&Path>) -> Result<(), Error> {
        self.deserialize_observed(input, source, None)
    }
    /// Deserialize using a borrowed local observer. Some overrides persistent
    /// observation for this operation and every nested include/secret file.
    pub fn deserialize_observed(
        &mut self,
        input: &[u8],
        source: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        let mut load = Load::observed(observer);
        self.admit_input(input.len(), &mut load)?;
        self.deserialize_inner(input, source, None, &mut load)
    }
    fn syntax(source: Option<&Path>, line: usize) -> Error {
        Error::Syntax {
            source: source.map(Path::to_path_buf),
            line,
        }
    }
    fn admit_input(&self, size: usize, load: &mut Load<'_>) -> Result<(), Error> {
        if size > self.limits.max_input_bytes {
            return Err(Error::Capacity);
        }
        load.bytes = load.bytes.checked_add(size).ok_or(Error::Capacity)?;
        if load.bytes > self.limits.max_loaded_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn deserialize_inner(
        &mut self,
        input: &[u8],
        source: Option<&Path>,
        restricted: Option<&[u8]>,
        load: &mut Load<'_>,
    ) -> Result<(), Error> {
        let observer = load.observer;
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut section: Option<Vec<u8>> = None;
        for (nr, raw) in input.split(|b| *b == b'\n').enumerate() {
            if raw.is_empty() {
                continue;
            }
            let line: Vec<u8> = raw
                .iter()
                .map(|b| if matches!(b, b'\t' | b'\r') { b' ' } else { *b })
                .collect();
            if line.iter().all(|b| *b == b' ') {
                continue;
            }
            let profile = self.case_context.snapshot();
            let value = profile.trim(&line);
            if matches!(value.first(), Some(b'#' | b'%')) {
                continue;
            }
            if value.starts_with(b"@") {
                if let Some(section) = restricted {
                    return Err(self.syntax_report(
                        observer,
                        source,
                        nr + 1,
                        "config.deserialize.restricted",
                        918,
                        b"Illegal directive in line %u (parsing restricted section %s)\n",
                        &[A::Unsigned((nr + 1) as u64), A::Bytes(section)],
                    ));
                }
                let end = value[1..]
                    .iter()
                    .position(|b| *b == b'@')
                    .map(|n| n + 1)
                    .ok_or_else(|| {
                        self.syntax_report(
                            observer,
                            source,
                            nr + 1,
                            "config.deserialize.bad-directive",
                            927,
                            b"Bad directive in line %u\n",
                            &[A::Unsigned((nr + 1) as u64)],
                        )
                    })?;
                let directive = &value[1..end];
                let args = profile.trim(&value[end + 1..]);
                let (pattern, secret) = if self.case_equals(directive, b"INLINE-SECRET") {
                    let space = args.iter().position(|b| *b == b' ').ok_or_else(|| {
                        self.syntax_report(
                            observer,
                            source,
                            nr + 1,
                            "config.deserialize.bad-secret",
                            983,
                            b"Bad inline-secret directive in line %u\n",
                            &[A::Unsigned((nr + 1) as u64)],
                        )
                    })?;
                    (profile.trim(&args[space + 1..]), Some(&args[..space]))
                } else if self.case_equals(directive, b"INLINE")
                    || self.case_equals(directive, b"INLINE-MATCHING")
                {
                    (args, None)
                } else {
                    return Err(self.syntax_report(
                        observer,
                        source,
                        nr + 1,
                        "config.deserialize.unknown-directive",
                        1006,
                        b"Unknown or malformed directive '%s' in line %u\n",
                        &[A::Bytes(directive), A::Unsigned((nr + 1) as u64)],
                    ));
                };
                let source=source.ok_or_else(||{
                    self.note_to(observer,"config.inline.no-source",Level::DEBUG,b"handle_inline",506,b"Refusing to parse inline configurations, not allowed without source filename!\n",&[]);
                    Self::syntax(source,nr+1)
                })?;
                let path = if pattern.starts_with(b"/") {
                    bytes_path(pattern)?
                } else {
                    let canonical = fs::canonicalize(source).map_err(|e| {
                        self.report_break(
                            observer,
                            Site {
                                id: "config.inline.source-unresolved",
                                file: b"configuration.c",
                                function: b"handle_inline",
                                line: 526,
                            },
                        );
                        io_error(source, e)
                    })?;
                    canonical
                        .parent()
                        .ok_or(Error::InvalidInput)?
                        .join(bytes_path(pattern)?)
                };
                if let Some(secret) = secret {
                    self.inline_secret(secret, &path, source, nr + 1, load)?;
                } else if self.case_equals(directive, b"INLINE-MATCHING") {
                    self.note_to(
                        observer,
                        "config.inline.glob",
                        Level::DEBUG,
                        b"handle_inline",
                        547,
                        b"processing config glob '%s'\n",
                        &[A::Bytes(path_bytes(&path)?)],
                    );
                    for path in glob::matching_files(
                        self,
                        observer,
                        &path,
                        self.limits.max_glob_matches,
                        self.limits.max_glob_scan_entries,
                    )? {
                        self.parse_inner(&path, load, None)?;
                    }
                } else {
                    self.parse_inner(&path, load, None)?;
                }
                continue;
            }
            // The pinned C indexes the original physical line length after
            // advancing/removing whitespace. Indented section headers can read
            // outside the allocation; safe Rust rejects that undefined case.
            if value.starts_with(b"[") && value.ends_with(b"]") && line.as_slice() == value {
                section = Some(value[1..value.len() - 1].to_vec());
                continue;
            }
            let eq = value.iter().position(|b| *b == b'=').ok_or_else(|| {
                self.syntax_report(
                    observer,
                    source,
                    nr + 1,
                    "config.deserialize.syntax",
                    1084,
                    b"Syntax error while deserializing in line %u\n",
                    &[A::Unsigned((nr + 1) as u64)],
                )
            })?;
            let section = section.as_deref().ok_or_else(|| {
                self.syntax_report(
                    observer,
                    source,
                    nr + 1,
                    "config.deserialize.no-section",
                    1034,
                    b"Syntax error while deserializing in line %u (option without section)\n",
                    &[A::Unsigned((nr + 1) as u64)],
                )
            })?;
            let mut key = &value[..eq];
            while key.len() > 1 && profile.is_space(key[key.len() - 1]) {
                key = &key[..key.len() - 1];
            }
            let mut value = profile.trim(&value[eq + 1..]);
            if value.starts_with(b"\"") && value.ends_with(b"\"") {
                value = if value.len() == 1 {
                    b""
                } else {
                    &value[1..value.len() - 1]
                };
            }
            if self.diagnostics && self.definitions >= self.limits.max_definitions {
                return Err(Error::Capacity);
            }
            self.set_value_observed(section, key, Some(value), load.observer)?;
            if self.diagnostics {
                let definition = Definition {
                    value: value.to_vec(),
                    filename: source.map_or_else(|| PathBuf::from("<input>"), Path::to_path_buf),
                    line: nr + 1,
                };
                let (s, e) = self.entry_index(section, key).ok_or(Error::Missing)?;
                self.sections[s].entries[e].sources.insert(0, definition);
                self.definitions += 1;
            }
        }
        Ok(())
    }
    /// Parse one official configuration file with bounded includes. Relative
    /// includes resolve against the canonical source target, including symlinks.
    pub fn parse(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.parse_with_environment(path, &ProcessEnvironment)
    }
    /// Parse using an explicit filename-expansion environment.
    pub fn parse_with_environment(
        &mut self,
        path: impl AsRef<Path>,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        self.parse_observed(path, environment, None)
    }
    /// Parse with a borrowed local observer. Some replaces persistent
    /// observation for this operation and nested include/secret files.
    pub fn parse_observed(
        &mut self,
        path: impl AsRef<Path>,
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        let hint = path.as_ref().to_path_buf();
        let path = self.expand_filename_observed(path_bytes(&hint)?, environment, observer)?;
        let index = self.files.len();
        let result = self.parse_inner(&path, &mut Load::observed(observer), None);
        if let Some(file) = self.files.get_mut(index) {
            file.filename = hint;
        }
        result
    }
    fn parse_inner(
        &mut self,
        path: &Path,
        load: &mut Load<'_>,
        restricted: Option<&[u8]>,
    ) -> Result<(), Error> {
        let observer = load.observer;
        self.note_to(
            observer,
            "config.parse.asked",
            Level::DEBUG,
            b"GNUNET_CONFIGURATION_parse",
            1112,
            b"Asked to parse config file `%s'\n",
            &[A::Bytes(path_bytes(path)?)],
        );
        if load.stack.len() >= self.limits.max_include_depth
            || load.files >= self.limits.max_files
            || self.files.len() >= self.limits.max_files
        {
            return Err(Error::Capacity);
        }
        let canonical = fs::canonicalize(path);
        if canonical
            .as_ref()
            .is_ok_and(|path| load.stack.contains(path))
        {
            let first = load
                .stack
                .iter()
                .position(|v| canonical.as_ref().is_ok_and(|p| p == v))
                .ok_or(Error::Cycle)?;
            let origin = &load.stack[first];
            if first + 1 == load.stack.len() {
                self.note_to(
                    observer,
                    "config.parse.cycle-direct",
                    Level::ERROR,
                    b"GNUNET_CONFIGURATION_parse",
                    1141,
                    b"Forbidden direct cyclic configuration import (%s -> %s)\n",
                    &[A::Bytes(path_bytes(origin)?), A::Bytes(path_bytes(path)?)],
                );
            } else {
                let parent = load.stack.last().ok_or(Error::Cycle)?;
                self.note_to(
                    observer,
                    "config.parse.cycle-indirect",
                    Level::ERROR,
                    b"GNUNET_CONFIGURATION_parse",
                    1148,
                    b"Forbidden indirect cyclic configuration import (%s -> ... -> %s -> %s)\n",
                    &[
                        A::Bytes(path_bytes(origin)?),
                        A::Bytes(path_bytes(parent)?),
                        A::Bytes(path_bytes(path)?),
                    ],
                );
            }
            return Err(Error::Cycle);
        }
        let file_index = self.files.len();
        self.files.push(FileSource {
            filename: path.to_path_buf(),
            level: load.stack.len(),
            restrict_section: None,
            inaccessible: false,
            contents: None,
        });
        load.files += 1;
        let canonical = canonical.map_err(|e| {
            let (syscall, line, id, actual) = match fs::symlink_metadata(path) {
                Err(error) => (b"lstat".as_slice(), 164, "config.disk.lstat", error),
                Ok(metadata) if metadata.file_type().is_symlink() => (
                    b"realpath".as_slice(),
                    178,
                    "config.disk.realpath",
                    copy_io_error(&e),
                ),
                Ok(_) => (
                    b"lstat".as_slice(),
                    164,
                    "config.disk.lstat",
                    copy_io_error(&e),
                ),
            };
            self.emit_to(
                observer,
                Diagnostic {
                    level: Level::DEBUG,
                    component: Some(b"util-disk"),
                    site: Site {
                        id,
                        file: b"disk.c",
                        function: b"get_size_rec",
                        line,
                    },
                    domain: Some(b"gnunet"),
                    template: b"`%s' failed on file `%s' at %s:%d with error: %s\n",
                    arguments: &[
                        A::Bytes(syscall),
                        A::Bytes(path.as_os_str().as_encoded_bytes()),
                        A::Bytes(b"disk.c"),
                        A::Signed(i64::from(line)),
                        A::Error(&actual),
                    ],
                },
            );
            self.note_to(
                observer,
                "config.parse.file-size",
                Level::WARNING,
                b"GNUNET_CONFIGURATION_parse",
                1178,
                b"Error while determining the file size of `%s'\n",
                &[A::Bytes(path.as_os_str().as_encoded_bytes())],
            );
            io_error(path, e)
        })?;
        if !fs::metadata(path).map_err(|e| io_error(path, e))?.is_file() {
            self.note_to(
                observer,
                "config.parse.file-size",
                Level::WARNING,
                b"GNUNET_CONFIGURATION_parse",
                1178,
                b"Error while determining the file size of `%s'\n",
                &[A::Bytes(path_bytes(path)?)],
            );
            return Err(Error::InvalidInput);
        }
        let file = open_regular(path).inspect_err(|error| {
            if let Error::Io { error, .. } = error {
                self.emit_to(
                    observer,
                    Diagnostic {
                        level: Level::WARNING,
                        component: Some(b"util-disk"),
                        site: Site {
                            id: "config.disk.open",
                            file: b"disk.c",
                            function: b"GNUNET_DISK_file_open",
                            line: 1367,
                        },
                        domain: Some(b"gnunet"),
                        template: b"`%s' failed on file `%s' at %s:%d with error: %s\n",
                        arguments: &[
                            A::Bytes(b"open"),
                            A::Bytes(path.as_os_str().as_encoded_bytes()),
                            A::Bytes(b"disk.c"),
                            A::Signed(1367),
                            A::Error(error),
                        ],
                    },
                );
            }
            self.note_to(
                observer,
                "config.parse.read",
                Level::WARNING,
                b"GNUNET_CONFIGURATION_parse",
                1197,
                b"Error while reading file `%s'\n",
                &[A::Bytes(path.as_os_str().as_encoded_bytes())],
            );
        })?;
        let mut input = Vec::new();
        let maximum = self
            .limits
            .max_input_bytes
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        file.take(maximum as u64)
            .read_to_end(&mut input)
            .map_err(|e| {
                self.note_to(
                    observer,
                    "config.parse.read",
                    Level::WARNING,
                    b"GNUNET_CONFIGURATION_parse",
                    1197,
                    b"Error while reading file `%s'\n",
                    &[A::Bytes(path.as_os_str().as_encoded_bytes())],
                );
                io_error(path, e)
            })?;
        self.admit_input(input.len(), load)?;
        if self.diagnostics
            && self
                .files
                .iter()
                .filter_map(|f| f.contents.as_ref())
                .map(Vec::len)
                .sum::<usize>()
                .checked_add(input.len())
                .is_none_or(|n| n > self.limits.max_loaded_bytes)
        {
            return Err(Error::Capacity);
        }
        load.stack.push(canonical);
        let dirty = self.dirty;
        self.note_to(
            observer,
            "config.parse.deserialize",
            Level::DEBUG,
            b"GNUNET_CONFIGURATION_parse",
            1210,
            b"Deserializing contents of file `%s'\n",
            &[A::Bytes(path_bytes(path)?)],
        );
        let result = self.deserialize_inner(&input, Some(path), restricted, load);
        if result.is_err() {
            self.emit_to(
                observer,
                Diagnostic {
                    level: Level::ERROR,
                    component: None,
                    site: Site {
                        id: "config.parse.failed",
                        file: b"configuration.c",
                        function: b"GNUNET_CONFIGURATION_parse",
                        line: 1219,
                    },
                    domain: Some(b"gnunet"),
                    template: b"Failed to parse configuration file `%s'\n",
                    arguments: &[A::Bytes(path_bytes(path)?)],
                },
            );
        }
        self.dirty = dirty;
        load.stack.pop();
        if result.is_ok() && self.diagnostics {
            self.files[file_index].contents = Some(input);
        }
        result
    }
    fn inline_secret(
        &mut self,
        name: &[u8],
        path: &Path,
        source: &Path,
        line: usize,
        load: &mut Load<'_>,
    ) -> Result<(), Error> {
        let observer = load.observer;
        if self.files.len() >= self.limits.max_files {
            return Err(Error::Capacity);
        }
        let index = self.ensure_section(name)?;
        if self.diagnostics {
            self.sections[index].secret_file = Some(path.to_path_buf());
            self.sections[index].secret_origin = Some((source.to_path_buf(), line));
            self.sections[index].secret_stat = Some(crate::accounts::secret_stat(path)?);
        }
        let file_index = self.files.len();
        self.files.push(FileSource {
            filename: path.to_path_buf(),
            level: load.stack.len(),
            restrict_section: Some(name.to_vec()),
            inaccessible: false,
            contents: None,
        });
        if !self.file_test_observed(path, true, observer) {
            self.sections[index].inaccessible = true;
            self.files[file_index].inaccessible = true;
            return Ok(());
        }
        let mut other = self.fresh()?;
        other.diagnostics = self.diagnostics;
        let result = other.parse_inner(path, load, Some(name));
        if result.is_err() {
            self.files[file_index].inaccessible = true;
            return result;
        }
        if let Some(index) = other.section_index(name) {
            for entry in &other.sections[index].entries {
                let additional = entry.sources.len();
                if self
                    .definitions
                    .checked_add(additional)
                    .is_none_or(|n| n > self.limits.max_definitions)
                {
                    return Err(Error::Capacity);
                }
                self.set_value_observed(name, &entry.key, entry.value.as_deref(), observer)?;
                let (s, e) = self.entry_index(name, &entry.key).ok_or(Error::Missing)?;
                let mut sources = entry.sources.clone();
                sources.append(&mut self.sections[s].entries[e].sources);
                self.sections[s].entries[e].sources = sources;
                self.definitions += additional;
            }
        } else {
            self.note_to(observer,"config.inline.secret-absent",Level::INFO,b"handle_inline",666,b"Configuration file '%s' loaded with @inline-secret@ does not contain section '%s'.\n",&[A::Bytes(path_bytes(path)?),A::Bytes(name)]);
        }
        Ok(())
    }
    /// Load only `.conf` files from a directory in byte-sorted path order.
    /// Returns the number parsed; non-`.conf` entries are skipped.
    pub fn load_from(&mut self, directory: impl AsRef<Path>) -> Result<usize, Error> {
        Ok(self.load_from_report(directory)?.files_loaded)
    }
    /// Load sorted defaults and retain the exact empty-directory versus
    /// ignored-entry distinction of the official return value.
    pub fn load_from_report(
        &mut self,
        directory: impl AsRef<Path>,
    ) -> Result<DirectoryLoad, Error> {
        self.load_from_observed(directory, None)
    }
    /// Load sorted defaults with a borrowed observer replacing persistent
    /// observation for every file and nested include in this operation.
    pub fn load_from_observed(
        &mut self,
        directory: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<DirectoryLoad, Error> {
        let directory = self.expand_filename_observed(
            path_bytes(directory.as_ref())?,
            &ProcessEnvironment,
            observer,
        )?;
        let entries = fs::read_dir(&directory).map_err(|error| {
            self.syscall(
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
        for entry in entries {
            if paths.len() >= self.limits.max_glob_scan_entries {
                return Err(Error::Capacity);
            }
            paths.push(entry.map_err(|e| io_error(&directory, e))?.path());
        }
        paths.sort();
        let entries_seen = paths.len();
        let mut count = 0;
        let mut load = Load::observed(observer);
        for path in paths {
            if path.extension().is_some_and(|v| v == "conf") {
                self.parse_inner(&path, &mut load, None)?;
                count += 1;
            } else {
                self.emit_to(
                    observer,
                    Diagnostic {
                        level: Level::WARNING,
                        component: None,
                        site: Site {
                            id: "config.load-from.skipping",
                            file: b"configuration.c",
                            function: b"GNUNET_CONFIGURATION_load_from",
                            line: 3222,
                        },
                        domain: None,
                        template: b"Skipping file `%s'\n",
                        arguments: &[A::Bytes(path_bytes(&path)?)],
                    },
                );
            }
        }
        Ok(DirectoryLoad {
            entries_seen,
            files_loaded: count,
        })
    }
    /// Official loader: base-config environment override, otherwise installed
    /// DATADIR/config.d, followed by the explicitly supplied main file. Passing
    /// None loads defaults only; default-filename discovery is a separate API.
    pub fn load(&mut self, main: Option<&Path>) -> Result<(), Error> {
        self.load_observed(main, None)
    }
    /// Native loader with a borrowed observer replacing persistent observation
    /// across defaults, main and nested configuration files.
    pub fn load_observed(
        &mut self,
        main: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.begin_load(main, observer);
        let environment = ProcessEnvironment;
        let defaults = if let Some(value) = self
            .project
            .base_config_varname
            .as_deref()
            .and_then(|name| environment.variable(name))
        {
            self.expand_filename_observed(&value, &environment, observer)?
        } else {
            let installation = self.installation_now().and_then(|installation| {
                installation
                    .path(PathKind::Datadir)
                    .ok_or(Error::Missing)
                    .map(Path::to_path_buf)
            });
            match installation {
                Ok(directory) => directory.join("config.d"),
                Err(error) => {
                    self.report_break(
                        observer,
                        Site {
                            id: "config.load.installation-missing",
                            file: b"configuration.c",
                            function: b"GNUNET_CONFIGURATION_load",
                            line: 3323,
                        },
                    );
                    return Err(error);
                }
            }
        };
        self.load_body(Some(&defaults), main, observer)
    }
    /// Load a caller-resolved official defaults directory followed by an optional
    /// main file. Missing defaults are allowed; a specified main file is required.
    /// Set `[PATHS] DEFAULTCONFIG` only when absent, as the official loader does.
    pub fn load_explicit(
        &mut self,
        defaults: Option<&Path>,
        main: Option<&Path>,
    ) -> Result<(), Error> {
        self.load_explicit_observed(defaults, main, None)
    }
    /// Explicit loader with synchronous operation-local observation. Some
    /// replaces persistent observation throughout this operation and escapes
    /// neither into the configuration nor into any duplicate handle.
    pub fn load_explicit_observed(
        &mut self,
        defaults: Option<&Path>,
        main: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.begin_load(main, observer);
        self.load_body(defaults, main, observer)
    }
    fn begin_load(
        &mut self,
        main: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) {
        if self.load_called {
            self.report_break(
                observer,
                Site {
                    id: "config.load.repeated",
                    file: b"configuration.c",
                    function: b"GNUNET_CONFIGURATION_load",
                    line: 3298,
                },
            );
        }
        self.load_called = true;
        self.main_filename = main.map(Path::to_path_buf);
    }
    fn load_body(
        &mut self,
        defaults: Option<&Path>,
        main: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        if let Some(defaults) = defaults {
            let path = self.expand_filename_observed(
                path_bytes(defaults)?,
                &ProcessEnvironment,
                observer,
            )?;
            if self.directory_test(observer, &path, true).unwrap_or(false)
                && let Err(error) = self.load_from_observed(path, observer)
            {
                self.note_to(
                    observer,
                    "config.load.base-failed",
                    Level::WARNING,
                    b"GNUNET_CONFIGURATION_load",
                    3347,
                    b"Failed to load base configuration from '%s'\n",
                    &[main.map_or(A::NullString, |path| {
                        A::Bytes(path.as_os_str().as_encoded_bytes())
                    })],
                );
                return Err(error);
            }
        }
        if let Some(main) = main {
            if let Err(error) = self.parse_observed(main, &ProcessEnvironment, observer) {
                self.note_to(
                    observer,
                    "config.load.main-failed",
                    Level::WARNING,
                    b"GNUNET_CONFIGURATION_load",
                    3361,
                    b"Failed to load configuration from file '%s'\n",
                    &[A::Bytes(path_bytes(main)?)],
                );
                return Err(error);
            }
            if self
                .get_observed(b"PATHS", b"DEFAULTCONFIG", observer)
                .is_none()
            {
                self.set_value_observed(
                    b"PATHS",
                    b"DEFAULTCONFIG",
                    Some(path_bytes(main)?),
                    observer,
                )?;
            }
        }
        Ok(())
    }

    /// Copy current values using the reference duplicate operation's insertion
    /// semantics. Source diagnostics and deleted-value tombstones are not copied.
    pub fn duplicate(&self) -> Result<Self, Error> {
        let mut result = self.fresh()?;
        for (s, k, v) in self.entries() {
            result.set_value(s, k, Some(v))?;
        }
        Ok(result)
    }
    /// Return only values in `new` that differ from this defaults object.
    /// Missing new values are not emitted as deletion records, matching C.
    pub fn diff(&self, new: &Self) -> Result<Self, Error> {
        self.diff_observed(new, None)
    }
    /// Asymmetric difference with the source project-identity diagnostic routed
    /// through this operation's local observer. Shared ProjectData Arc identity
    /// corresponds to the original caller-owned pd pointer. Distinct project
    /// owners log the original break but do not prevent computing the difference.
    pub fn diff_observed(
        &self,
        new: &Self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.project, &new.project) {
            self.report_break(
                observer,
                Site {
                    id: "config.diff.project-mismatch",
                    file: b"configuration.c",
                    function: b"GNUNET_CONFIGURATION_get_diff",
                    line: 2345,
                },
            );
        }
        let mut result = new.fresh()?;
        for (s, k, v) in new.entries() {
            if self.get_observed(s, k, observer) != Some(v) {
                result.set_value_observed(s, k, Some(v), observer)?;
            }
        }
        Ok(result)
    }
    /// Write the asymmetric difference via a temporary configuration. The
    /// original objects' dirty indicators and diagnostic provenance are intact.
    pub fn write_diffs(&self, new: &Self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.write_diffs_observed(new, path, None)
    }
    /// Difference and publication using the same operation-local diagnostic
    /// identity, including the source project-pointer assertion and new owner.
    pub fn write_diffs_observed(
        &self,
        new: &Self,
        path: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.diff_observed(new, observer)?
            .write_observed(path, observer)
    }
    /// Create, load, invoke a callback exactly once on success, and release the
    /// complete temporary owner after the callback, preserving its result.
    pub fn parse_and_run<T>(
        project: Arc<ProjectData>,
        limits: Limits,
        filename: Option<&Path>,
        callback: impl FnOnce(&Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        Self::parse_and_run_observed(project, limits, filename, None, callback)
    }
    /// Fresh configuration callback lifetime with a borrowed diagnostic port.
    /// The observer follows loading and the source parse-and-run failure report;
    /// it is not installed into the configuration passed to the callback.
    pub fn parse_and_run_observed<T>(
        project: Arc<ProjectData>,
        limits: Limits,
        filename: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        callback: impl FnOnce(&Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut configuration = Self::create(project, limits)?;
        if let Err(error) = configuration.load_observed(filename, observer) {
            configuration.report_break(
                observer,
                Site {
                    id: "config.parse-and-run.failed",
                    file: b"configuration.c",
                    function: b"GNUNET_CONFIGURATION_parse_and_run",
                    line: 388,
                },
            );
            return Err(error);
        }
        callback(&configuration)
    }
    /// Serialize exactly the official section/key ordering and `key = value`
    /// syntax. Installation PATHS are omitted and literal LF becomes backslash-n;
    /// the official parser does not decode that backslash escape on reload.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for section in self.sections() {
            out.push(b'[');
            out.extend_from_slice(&section.name);
            out.extend_from_slice(b"]\n");
            for entry in &section.entries {
                if skip(&section.name, &entry.key, &self.case_context.snapshot()) {
                    continue;
                }
                if let Some(value) = &entry.value {
                    out.extend_from_slice(&entry.key);
                    out.extend_from_slice(b" = ");
                    escape_newlines(value, &mut out);
                    out.push(b'\n');
                }
            }
            out.push(b'\n');
            if out.len() > self.limits.max_expanded_bytes {
                return Err(Error::Capacity);
            }
        }
        Ok(out)
    }
    /// Atomically publish official serialized text to a sibling file and rename
    /// it over the existing target. Existing symlinks resolve to their target;
    /// file permissions are retained. Failure sets the dirty error indication.
    pub fn write(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.write_observed(path, None)
    }
    /// Publish trusted bytes produced by this owner's `serialize` through the
    /// existing native atomic writer. The caller owns/authorizes the exact target
    /// and retains sensitive contents in its own zeroizing buffer. This does not
    /// parse/reload includes or update another live configuration on success.
    /// Failure has the same dirty/error behavior as `write`; this shared port
    /// does not expose a separate publication-stage or temporary-cleanup receipt.
    pub fn write_serialized(
        &mut self,
        path: impl AsRef<Path>,
        contents: &[u8],
    ) -> Result<(), Error> {
        let result = if contents.len() > self.limits.max_expanded_bytes {
            Err(Error::Capacity)
        } else {
            self.atomic_write(path.as_ref(), contents, None, None)
        };
        self.dirty = if result.is_ok() {
            Dirty::Clean
        } else {
            Dirty::WriteFailed
        };
        result
    }

    /// Atomic publication with a synchronous local observer replacing the
    /// persistent route through filename, directory, write and commit checks.
    pub fn write_observed(
        &mut self,
        path: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        let result = self
            .serialize()
            .and_then(|bytes| self.atomic_write(path.as_ref(), &bytes, None, observer));
        self.dirty = if result.is_ok() {
            Dirty::Clean
        } else {
            Dirty::WriteFailed
        };
        result
    }
    fn atomic_write(
        &self,
        path: &Path,
        contents: &[u8],
        expected: Option<&[u8]>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        let mut path =
            self.expand_filename_observed(path_bytes(path)?, &ProcessEnvironment, observer)?;
        self.create_directory_for_file(&path, observer)?;
        if let Ok(canonical) = fs::canonicalize(&path) {
            path = canonical;
        }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let temporary = PathBuf::from(name);
        let mut created = false;
        let result = (|| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o660);
            }
            let mut file = options.open(&temporary).map_err(|error| {
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    Site {
                        id: "config.disk.open",
                        file: b"disk.c",
                        function: b"GNUNET_DISK_file_open",
                        line: 1367,
                    },
                    Level::WARNING,
                    b"open",
                    &temporary,
                    &error,
                );
                io_error(&temporary, error)
            })?;
            created = true;
            file.write_all(contents).map_err(|error| {
                self.syscall(
                    observer,
                    None,
                    Site {
                        id: "config.write.write",
                        file: b"configuration.c",
                        function: b"write_buffer_atomic",
                        line: 1748,
                    },
                    Level::WARNING,
                    b"write",
                    &temporary,
                    &error,
                );
                io_error(&temporary, error)
            })?;
            file.sync_all().map_err(|error| {
                self.syscall(
                    observer,
                    None,
                    Site {
                        id: "config.write.fsync",
                        file: b"configuration.c",
                        function: b"write_buffer_atomic",
                        line: 1761,
                    },
                    Level::WARNING,
                    b"fsync",
                    &temporary,
                    &error,
                );
                io_error(&temporary, error)
            })?;
            // The source checks close before chmod/hash/rename. OwnedFd is
            // consumed by the safe nix wrapper; no stale descriptor is retained.
            #[cfg(unix)]
            {
                let descriptor: std::os::fd::OwnedFd = file.into();
                nix::unistd::close(descriptor).map_err(|error| {
                    let error = std::io::Error::from_raw_os_error(error as i32);
                    self.syscall(
                        observer,
                        None,
                        Site {
                            id: "config.write.close",
                            file: b"configuration.c",
                            function: b"write_buffer_atomic",
                            line: 1772,
                        },
                        Level::WARNING,
                        b"close",
                        &temporary,
                        &error,
                    );
                    io_error(&temporary, error)
                })?;
            }
            #[cfg(not(unix))]
            drop(file);
            if let Ok(metadata) = fs::metadata(&path) {
                let mut permissions = metadata.permissions();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    permissions = fs::Permissions::from_mode(permissions.mode() & 0o777);
                }
                if let Err(error) = fs::set_permissions(&temporary, permissions) {
                    // chmod is diagnostic-only in the source; publication is
                    // still attempted after this warning.
                    self.syscall(
                        observer,
                        None,
                        Site {
                            id: "config.write.chmod",
                            file: b"configuration.c",
                            function: b"write_buffer_atomic",
                            line: 1790,
                        },
                        Level::WARNING,
                        b"chmod",
                        &temporary,
                        &error,
                    );
                }
            }
            if let Some(expected) = expected
                && !self
                    .read_checked_contents(&path, observer)
                    .is_ok_and(|contents| contents == expected)
            {
                self.note_to(
                    observer,
                    "config.write.changed",
                    Level::ERROR,
                    b"write_buffer_atomic",
                    1798,
                    b"Configuration file `%s' changed while it was being cleaned\n",
                    &[A::Bytes(path_bytes(&path)?)],
                );
                return Err(Error::Changed);
            }
            fs::rename(&temporary, &path).map_err(|error| {
                self.syscall(
                    observer,
                    None,
                    Site {
                        id: "config.write.rename",
                        file: b"configuration.c",
                        function: b"write_buffer_atomic",
                        line: 1809,
                    },
                    Level::WARNING,
                    b"rename",
                    &path,
                    &error,
                );
                io_error(&path, error)
            })
        })();
        if result.is_err() && created {
            match fs::remove_file(&temporary) {
                Ok(()) | Err(_) => {}
            }
        }
        result
    }
    /// Source DISK file-test read point with explicit filename environment and
    /// borrowed diagnostics. Missing HOME is a false test; capacity/host errors
    /// remain explicit Rust failures rather than being mistaken for absence.
    pub fn test_file(
        &self,
        path: &Path,
        readable: bool,
        environment: &impl Environment,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<bool, Error> {
        let path = match self.expand_filename_observed(path_bytes(path)?, environment, observer) {
            Ok(path) => path,
            Err(Error::Missing) => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(self.file_test_observed(&path, readable, observer))
    }
    pub(crate) fn file_test_observed(
        &self,
        path: &Path,
        readable: bool,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> bool {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.syscall(
                        observer,
                        Some(b"util-disk"),
                        Site {
                            id: "config.disk.file-stat",
                            file: b"disk.c",
                            function: b"file_test_internal",
                            line: 531,
                        },
                        Level::DEBUG,
                        b"stat",
                        path,
                        &error,
                    );
                }
                return false;
            }
        };
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        if let Err(error) = nix::unistd::access(
            path,
            if readable {
                nix::unistd::AccessFlags::R_OK
            } else {
                nix::unistd::AccessFlags::F_OK
            },
        ) {
            let error = std::io::Error::from_raw_os_error(error as i32);
            self.syscall(
                observer,
                Some(b"util-disk"),
                Site {
                    id: "config.disk.file-access",
                    file: b"disk.c",
                    function: b"file_test_internal",
                    line: 547,
                },
                Level::DEBUG,
                b"access",
                path,
                &error,
            );
            return false;
        }
        #[cfg(not(unix))]
        if readable {
            return false;
        }
        true
    }
    fn directory_test(
        &self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        path: &Path,
        readable: bool,
    ) -> Result<bool, Error> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.syscall(
                        observer,
                        Some(b"util-disk"),
                        Site {
                            id: "config.disk.directory-stat",
                            file: b"disk.c",
                            function: b"GNUNET_DISK_directory_test",
                            line: 478,
                        },
                        Level::WARNING,
                        b"stat",
                        path,
                        &error,
                    );
                }
                return Err(io_error(path, error));
            }
        };
        if !metadata.is_dir() {
            self.emit_to(
                observer,
                Diagnostic {
                    level: Level::INFO,
                    component: Some(b"util-disk"),
                    site: Site {
                        id: "config.disk.directory-file",
                        file: b"disk.c",
                        function: b"GNUNET_DISK_directory_test",
                        line: 485,
                    },
                    domain: None,
                    template: b"A file already exits with the same name %s\n",
                    arguments: &[A::Bytes(path_bytes(path)?)],
                },
            );
            return Ok(false);
        }
        #[cfg(unix)]
        {
            let access = nix::unistd::AccessFlags::X_OK
                | if readable {
                    nix::unistd::AccessFlags::R_OK
                } else {
                    nix::unistd::AccessFlags::empty()
                };
            if let Err(error) = nix::unistd::access(path, access) {
                let error = std::io::Error::from_raw_os_error(error as i32);
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    Site {
                        id: "config.disk.directory-access",
                        file: b"disk.c",
                        function: b"GNUNET_DISK_directory_test",
                        line: 498,
                    },
                    Level::WARNING,
                    b"access",
                    path,
                    &error,
                );
                return Ok(false);
            }
        }
        #[cfg(not(unix))]
        if readable {
            return Err(Error::Unsupported);
        }
        Ok(true)
    }
    fn create_directory_for_file(
        &self,
        path: &Path,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        #[cfg(unix)]
        if nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok() {
            return Ok(());
        }
        let parent = path.parent().ok_or(Error::InvalidInput)?;
        let mut missing = Vec::new();
        let mut current = parent;
        loop {
            match self.directory_test(observer, current, false) {
                Ok(true) => break,
                Ok(false) => {
                    self.directory_create_failed(current, observer)?;
                    return Err(Error::InvalidInput);
                }
                Err(_) => missing.push(current.to_path_buf()),
            }
            let Some(next) = current.parent() else {
                return Err(Error::InvalidInput);
            };
            current = next;
        }
        for directory in missing.iter().rev() {
            match self.directory_test(observer, directory, false) {
                Ok(true) => continue,
                Ok(false) => {
                    self.directory_create_failed(directory, observer)?;
                    return Err(Error::InvalidInput);
                }
                Err(_) => {}
            }
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o755);
            }
            if let Err(error) = builder.create(directory)
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    Site {
                        id: "config.disk.mkdir",
                        file: b"disk.c",
                        function: b"GNUNET_DISK_directory_create",
                        line: 649,
                    },
                    Level::ERROR,
                    b"mkdir",
                    directory,
                    &error,
                );
                return Err(io_error(directory, error));
            }
        }
        #[cfg(unix)]
        nix::unistd::access(parent, nix::unistd::AccessFlags::W_OK)
            .map_err(|error| io_error(parent, std::io::Error::from_raw_os_error(error as i32)))?;
        Ok(())
    }
    fn directory_create_failed(
        &self,
        path: &Path,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        self.emit_to(
            observer,
            Diagnostic {
                level: Level::ERROR,
                component: None,
                site: Site {
                    id: "config.disk.directory-create-failed",
                    file: b"disk.c",
                    function: b"GNUNET_DISK_directory_create",
                    line: 606,
                },
                domain: None,
                template: b"Creating directory `%s' failed\n",
                arguments: &[A::Bytes(path_bytes(path)?)],
            },
        );
        Ok(())
    }
    /// Return official filename-list tokens, unescaping only backslash-space
    /// and backslash-backslash after the first byte of each token, as in C.
    pub fn filenames(&self, section: &[u8], key: &[u8]) -> Vec<Vec<u8>> {
        let Some(value) = self.get(section, key) else {
            return Vec::new();
        };
        let mut value = value.to_vec();
        let mut out = Vec::new();
        let mut start = 0;
        while start < value.len() {
            while value.get(start) == Some(&b' ') {
                start += 1;
            }
            if start == value.len() {
                break;
            }
            let mut end = start + 1;
            while end < value.len() && value[end] != b' ' {
                if value[end] == b'\\'
                    && value
                        .get(end + 1)
                        .is_some_and(|b| matches!(b, b'\\' | b' '))
                {
                    value.remove(end);
                }
                end += 1;
            }
            out.push(value[start..end].to_vec());
            start = end + 1;
        }
        out
    }
    /// Append an escaped filename only if no existing decoded token equals it.
    pub fn append_filename(
        &mut self,
        section: &[u8],
        key: &[u8],
        filename: &[u8],
    ) -> Result<bool, Error> {
        self.checked_string(filename)?;
        if self.filenames(section, key).iter().any(|v| v == filename) {
            return Ok(false);
        }
        let mut value = self.get(section, key).unwrap_or_default().to_vec();
        if !value.is_empty() {
            value.push(b' ');
        }
        escape_filename(filename, &mut value);
        self.set_value(section, key, Some(&value))?;
        Ok(true)
    }
    /// Remove the first encoded filename-list token equal to the escaped name.
    pub fn remove_filename(
        &mut self,
        section: &[u8],
        key: &[u8],
        filename: &[u8],
    ) -> Result<bool, Error> {
        self.checked_string(filename)?;
        let Some(value) = self.get(section, key) else {
            return Ok(false);
        };
        let mut value = value.to_vec();
        let mut escaped = Vec::new();
        escape_filename(filename, &mut escaped);
        let mut start = 0;
        while start < value.len() {
            while value.get(start) == Some(&b' ') {
                start += 1;
            }
            if start == value.len() {
                break;
            }
            let mut end = start + 1;
            while end < value.len() && value[end] != b' ' {
                if value[end] == b'\\'
                    && value
                        .get(end + 1)
                        .is_some_and(|b| matches!(b, b'\\' | b' '))
                {
                    end += 1;
                }
                end += 1;
            }
            if value[start..end] == escaped {
                if end < value.len() {
                    value.drain(start..end + 1);
                } else {
                    value.truncate(start.saturating_sub(usize::from(start != 0)));
                }
                self.set_value(section, key, Some(&value))?;
                return Ok(true);
            }
            start = end + 1;
        }
        Ok(false)
    }
    /// Remove redundant physical assignments from a previously diagnostic-parsed
    /// file while preserving every effective setting and all other bytes. Reject
    /// if the file changed since parsing or before its atomic replacement.
    pub fn clean_file(&self, path: impl AsRef<Path>) -> Result<Vec<usize>, Error> {
        self.clean_file_observed(path, None)
    }
    /// Clean with immediate local diagnostics through read/hash and atomic
    /// publication; neither callback nor diagnostic borrow enters saved state.
    pub fn clean_file_observed(
        &self,
        path: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Vec<usize>, Error> {
        Ok(self
            .clean_file_records(path, observer)?
            .into_iter()
            .map(|r| r.line)
            .collect())
    }
    /// Publish a cleaned file then report each removed physical definition in
    /// line order. No callback runs on refusal or a failed atomic publication.
    pub fn clean_file_with(
        &self,
        path: impl AsRef<Path>,
        callback: impl FnMut(&CleanRemoval),
    ) -> Result<usize, Error> {
        self.clean_file_with_observed(path, None, callback)
    }
    /// Source line-removal callbacks after successful local-observed publication.
    pub fn clean_file_with_observed(
        &self,
        path: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
        mut callback: impl FnMut(&CleanRemoval),
    ) -> Result<usize, Error> {
        let removed = self.clean_file_records(path, observer)?;
        for line in &removed {
            callback(line);
        }
        Ok(removed.len())
    }
    // Source read_file()/file_hash_matches(): size/lstat (following a symlink
    // through realpath) precedes open/read. Sharing this one body keeps native
    // helper diagnostics in the original order for clean and publication checks.
    fn read_checked_contents(
        &self,
        path: &Path,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Vec<u8>, Error> {
        let size_site = |id, line| Site {
            id,
            file: b"disk.c",
            function: b"get_size_rec",
            line,
        };
        let mut selected = path.to_path_buf();
        let mut metadata = fs::symlink_metadata(&selected).map_err(|error| {
            self.syscall(
                observer,
                Some(b"util-disk"),
                size_site("config.disk.lstat", 164),
                Level::DEBUG,
                b"lstat",
                &selected,
                &error,
            );
            io_error(&selected, error)
        })?;
        if metadata.file_type().is_symlink() {
            selected = fs::canonicalize(path).map_err(|error| {
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    size_site("config.disk.realpath", 178),
                    Level::DEBUG,
                    b"realpath",
                    path,
                    &error,
                );
                io_error(path, error)
            })?;
            metadata = fs::symlink_metadata(&selected).map_err(|error| {
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    size_site("config.disk.lstat", 164),
                    Level::DEBUG,
                    b"lstat",
                    &selected,
                    &error,
                );
                io_error(&selected, error)
            })?;
        }
        if !metadata.is_file() {
            return Err(Error::InvalidInput);
        }
        let size = usize::try_from(metadata.len()).map_err(|_| Error::Capacity)?;
        if size > self.limits.max_input_bytes {
            return Err(Error::Capacity);
        }
        let mut file = open_regular(path).inspect_err(|error| {
            if let Error::Io { error, .. } = error {
                self.syscall(
                    observer,
                    Some(b"util-disk"),
                    Site {
                        id: "config.disk.open",
                        file: b"disk.c",
                        function: b"GNUNET_DISK_file_open",
                        line: 1367,
                    },
                    Level::WARNING,
                    b"open",
                    path,
                    error,
                );
            }
        })?;
        let mut contents = Vec::new();
        contents
            .try_reserve_exact(size)
            .map_err(|_| Error::Capacity)?;
        contents.resize(size, 0);
        file.read_exact(&mut contents)
            .map_err(|error| io_error(path, error))?;
        Ok(contents)
    }
    fn clean_file_records(
        &self,
        path: impl AsRef<Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Vec<CleanRemoval>, Error> {
        if !self.diagnostics {
            return Err(Error::InvalidInput);
        }
        let path = self.expand_filename_observed(
            path_bytes(path.as_ref())?,
            &ProcessEnvironment,
            observer,
        )?;
        let original = self
            .files
            .iter()
            .rev()
            .find(|file| {
                self.expand_filename_observed(
                    path_bytes(&file.filename).unwrap_or_default(),
                    &ProcessEnvironment,
                    observer,
                )
                .is_ok_and(|name| name == path)
                    && file.contents.is_some()
            })
            .and_then(|file| file.contents.as_deref());
        let Some(original) = original else {
            self.note_to(
                observer,
                "config.clean.not-parsed",
                Level::ERROR,
                b"GNUNET_CONFIGURATION_clean_file",
                1954,
                b"Configuration file `%s' was not parsed with diagnostics enabled\n",
                &[A::Bytes(path_bytes(&path)?)],
            );
            return Err(Error::Missing);
        };
        let current = self.read_checked_contents(&path, observer);
        if !current.as_ref().is_ok_and(|contents| contents == original) {
            let (id, line) = if current.is_err() {
                ("config.clean.read-changed", 1961)
            } else {
                ("config.clean.hash-changed", 1975)
            };
            self.note_to(
                observer,
                id,
                Level::ERROR,
                b"GNUNET_CONFIGURATION_clean_file",
                line,
                b"Configuration file `%s' changed since it was parsed\n",
                &[A::Bytes(path_bytes(&path)?)],
            );
            return Err(Error::Changed);
        }
        let mut removed = BTreeSet::new();
        for section in &self.sections {
            for entry in &section.entries {
                for source in &entry.sources {
                    if source.filename == path
                        && entry.sources.iter().any(|other| {
                            other.value == source.value
                                && (other.line != source.line || other.filename != source.filename)
                        })
                    {
                        removed.insert(source.line);
                    }
                }
            }
        }
        for section in &self.sections {
            for entry in &section.entries {
                let survivor = entry
                    .sources
                    .iter()
                    .find(|source| source.filename != path || !removed.contains(&source.line));
                if survivor
                    .is_some_and(|source| entry.value.as_deref() == Some(source.value.as_slice()))
                {
                    continue;
                }
                if let Some(source) = entry.sources.iter().find(|source| {
                    source.filename == path
                        && entry.value.as_deref() == Some(source.value.as_slice())
                        && removed.contains(&source.line)
                }) {
                    removed.remove(&source.line);
                }
            }
        }
        if removed.is_empty() {
            return Ok(Vec::new());
        }
        let mut cleaned = Vec::new();
        for (nr, line) in original.split_inclusive(|b| *b == b'\n').enumerate() {
            if !removed.contains(&(nr + 1)) {
                cleaned.extend_from_slice(line);
            }
        }
        let mut records = Vec::new();
        for line in removed {
            let (section, entry) = self
                .sections
                .iter()
                .find_map(|s| {
                    s.entries
                        .iter()
                        .find(|e| {
                            e.sources
                                .iter()
                                .any(|source| source.line == line && source.filename == path)
                        })
                        .map(|e| (s, e))
                })
                .ok_or(Error::Changed)?;
            records.push(CleanRemoval {
                section: section.name.clone(),
                option: entry.key.clone(),
                line,
            });
        }
        self.atomic_write(&path, &cleaned, Some(original), observer)?;
        Ok(records)
    }
}

fn skip(section: &[u8], key: &[u8], case: &CaseSnapshot) -> bool {
    case.equals(section, b"PATHS")
        && [
            b"DATADIR".as_slice(),
            b"LIBDIR",
            b"BINDIR",
            b"PREFIX",
            b"LOCALEDIR",
            b"ICONDIR",
            b"DOCDIR",
            b"DEFAULTCONFIG",
            b"LIBEXECDIR",
        ]
        .iter()
        .any(|name| case.equals(name, key))
}
fn escape_newlines(value: &[u8], output: &mut Vec<u8>) {
    for b in value {
        if *b == b'\n' {
            output.extend_from_slice(b"\\n");
        } else {
            output.push(*b);
        }
    }
}
fn escape_filename(value: &[u8], output: &mut Vec<u8>) {
    for b in value {
        if matches!(b, b'\\' | b' ') {
            output.push(b'\\');
        }
        output.push(*b);
    }
}

fn open_regular(path: &Path) -> Result<fs::File, Error> {
    #[cfg(unix)]
    let file = {
        use nix::{
            fcntl::{OFlag, open},
            sys::stat::Mode,
        };
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error(path, std::io::Error::from(error)))?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path).map_err(|error| io_error(path, error))?;
    if !file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .is_file()
    {
        return Err(Error::InvalidInput);
    }
    Ok(file)
}

impl Configuration {
    /// Visit decoded filename tokens until a callback returns false, which maps
    /// to the official SYSERR callback-abort result. Missing values yield zero.
    pub fn iterate_value_filenames(
        &self,
        section: &[u8],
        key: &[u8],
        mut callback: impl FnMut(&[u8]) -> bool,
    ) -> Result<usize, Error> {
        let names = self.filenames(section, key);
        let mut count = 0;
        for name in names {
            count += 1;
            if !callback(&name) {
                return Err(Error::IterationAborted);
            }
        }
        Ok(count)
    }
    /// Resolve helper paths with the process-global first-use caches present in
    /// the pinned C API. This resolves only; it never executes or changes modes.
    pub fn suid_binary_path(&self, program: &[u8]) -> Result<PathBuf, Error> {
        let mut cache = crate::project::global_binary_cache()
            .lock()
            .map_err(|_| Error::InvalidValue)?;
        self.suid_binary_path_with(program, &mut cache)
    }
    /// Resolve using an explicitly owned cache, for an independent embedding or
    /// isolated process-equivalent test context.
    pub fn suid_binary_path_with(
        &self,
        program: &[u8],
        cache: &mut BinaryPathCache,
    ) -> Result<PathBuf, Error> {
        self.suid_binary_path_resolve(program, cache, || self.installation_now())
    }
    /// Official independently selected project context. The configuration only
    /// supplies SUID_BINARY_PATH; when it is absent or empty, installation
    /// discovery uses `project`, which need not be this configuration's project.
    /// Process-first-use SUID/libexec caches still apply, exactly as in C.
    /// This constructs a path only; it never executes or changes a binary.
    pub fn suid_binary_path_for_project(
        &self,
        project: &ProjectData,
        program: &[u8],
    ) -> Result<PathBuf, Error> {
        let mut cache = crate::project::global_binary_cache()
            .lock()
            .map_err(|_| Error::InvalidValue)?;
        self.suid_binary_path_for_project_with(project, program, &mut cache)
    }
    /// Independently selected project with an explicitly owned cache. Reusing
    /// this cache preserves the first successful fallback's project, even when
    /// later calls pass another project. A fresh cache is a fresh process-like
    /// resolution context. Absolute paths bypass both discovery and caches.
    pub fn suid_binary_path_for_project_with(
        &self,
        project: &ProjectData,
        program: &[u8],
        cache: &mut BinaryPathCache,
    ) -> Result<PathBuf, Error> {
        self.suid_binary_path_resolve(program, cache, || {
            Installation::discover(project, &ProcessEnvironment)
        })
    }
    fn suid_binary_path_resolve(
        &self,
        program: &[u8],
        cache: &mut BinaryPathCache,
        installation: impl FnOnce() -> Result<Installation, Error>,
    ) -> Result<PathBuf, Error> {
        self.checked_string(program)?;
        if program.starts_with(b"/") {
            return bytes_path(program);
        }
        let path = cache
            .suid
            .as_deref()
            .or_else(|| self.get(b"PATHS", b"SUID_BINARY_PATH"));
        if let Some(path) = path.filter(|p| !p.is_empty()) {
            let mut full = path.to_vec();
            if !full.ends_with(b"/") {
                full.push(b'/');
            }
            full.extend_from_slice(program);
            if cache.suid.is_none() {
                cache.suid = Some(path.to_vec());
            }
            return bytes_path(&full);
        }
        cache.suid = None;
        if cache.libexec.is_none() {
            cache.libexec = installation()?
                .path(PathKind::Libexecdir)
                .map(Path::to_path_buf);
        }
        let Some(directory) = cache.libexec.as_deref() else {
            return bytes_path(program);
        };
        let mut full = path_bytes(directory)?.to_vec();
        full.extend_from_slice(program);
        bytes_path(&full)
    }
    /// Serialize complete official effective-source diagnostics. Secret values
    /// are included when loaded, just as in C; this is an explicitly requested
    /// diagnostic export, not a redacted log representation.
    pub fn serialize_diagnostics(&self) -> Result<Vec<u8>, Error> {
        self.diagnostic_text(false)
    }
    /// Serialize every physical definition with effective/same/different labels.
    pub fn serialize_diagnostics_verbose(&self) -> Result<Vec<u8>, Error> {
        self.diagnostic_text(true)
    }
    fn diagnostic_text(&self, verbose: bool) -> Result<Vec<u8>, Error> {
        let limit = self.limits.max_expanded_bytes;
        let mut out = Vec::new();
        text(
            &mut out,
            limit,
            &[
                b"#\n# Configuration file diagnostics\n#\n# Entry point: ",
                self.main_filename
                    .as_deref()
                    .map(path_bytes)
                    .transpose()?
                    .unwrap_or(b"<none>"),
                b"\n#\n# Files Loaded:\n",
            ],
        )?;
        for file in &self.files {
            text(&mut out, limit, &[b"# "])?;
            for _ in 0..file.level {
                text(&mut out, limit, &[b"+"])?;
            }
            if file.level != 0 {
                text(&mut out, limit, &[b" "])?;
            }
            text(&mut out, limit, &[path_bytes(&file.filename)?])?;
            if let Some(section) = &file.restrict_section {
                text(
                    &mut out,
                    limit,
                    &[
                        b" (",
                        if file.inaccessible {
                            b"inaccessible"
                        } else {
                            b"loaded"
                        },
                        b" secret section ",
                        section,
                        b")",
                    ],
                )?;
            }
            text(&mut out, limit, &[b"\n"])?;
        }
        text(&mut out, limit, &[b"#\n# Installation paths:\n"])?;
        let installation = self.installation_now()?;
        for kind in [
            PathKind::Datadir,
            PathKind::Libdir,
            PathKind::Bindir,
            PathKind::Prefix,
            PathKind::Localedir,
            PathKind::Icondir,
            PathKind::Docdir,
            PathKind::Libexecdir,
            PathKind::SelfPrefix,
        ] {
            text(
                &mut out,
                limit,
                &[
                    b"# ",
                    kind.diagnostic_name().as_bytes(),
                    b" = ",
                    installation
                        .path(kind)
                        .map(path_bytes)
                        .transpose()?
                        .unwrap_or(b"(null)"),
                    b"\n",
                ],
            )?;
        }
        text(&mut out, limit, &[b"#\n\n"])?;
        for section in &self.sections {
            if let Some(path) = section.secret_file.as_deref() {
                text(
                    &mut out,
                    limit,
                    &[
                        b"# secret section from ",
                        path_bytes(path)?,
                        b"\n# secret file stat ",
                        section.secret_stat.as_deref().ok_or(Error::Missing)?,
                        b"\n",
                    ],
                )?;
            }
            if let Some((path, line)) = &section.secret_origin {
                text(
                    &mut out,
                    limit,
                    &[
                        b"# inlined from ",
                        path_bytes(path)?,
                        b":",
                        line.to_string().as_bytes(),
                        b"\n",
                    ],
                )?;
            }
            text(&mut out, limit, &[b"[", &section.name, b"]\n\n"])?;
            if section.inaccessible && section.entries.is_empty() {
                text(
                    &mut out,
                    limit,
                    &[b"# <section contents inaccessible>\n\n\n"],
                )?;
                continue;
            }
            for entry in &section.entries {
                if skip(&section.name, &entry.key, &self.case_context.snapshot()) {
                    continue;
                }
                if let Some(value) = entry.value.as_deref() {
                    if let Some(source) = entry.sources.first() {
                        if verbose && entry.sources.len() > 1 {
                            text(
                                &mut out,
                                limit,
                                &[b"# duplicate definitions (highest precedence first):\n"],
                            )?;
                            for (index, source) in entry.sources.iter().enumerate() {
                                let status: &[u8] = if index == 0 {
                                    b"effective".as_slice()
                                } else if source.value == value {
                                    b"same value"
                                } else {
                                    b"different value"
                                };
                                text(
                                    &mut out,
                                    limit,
                                    &[
                                        b"#   ",
                                        path_bytes(&source.filename)?,
                                        b":",
                                        source.line.to_string().as_bytes(),
                                        b" (",
                                        status,
                                        b")\n",
                                    ],
                                )?;
                            }
                        } else {
                            text(
                                &mut out,
                                limit,
                                &[
                                    b"# ",
                                    path_bytes(&source.filename)?,
                                    b":",
                                    source.line.to_string().as_bytes(),
                                    b"\n",
                                ],
                            )?;
                        }
                    }
                    let mut escaped = Vec::new();
                    escape_newlines(value, &mut escaped);
                    text(&mut out, limit, &[&entry.key, b" = ", &escaped, b"\n"])?;
                }
                text(&mut out, limit, &[b"\n"])?;
            }
            if section.inaccessible {
                text(
                    &mut out,
                    limit,
                    &[b"# <additional section contents inaccessible>\n\n\n"],
                )?;
            } else {
                text(&mut out, limit, &[b"\n"])?;
            }
        }
        Ok(out)
    }
}
pub(crate) fn text(output: &mut Vec<u8>, limit: usize, parts: &[&[u8]]) -> Result<(), Error> {
    let size = parts.iter().try_fold(output.len(), |n, p| {
        n.checked_add(p.len()).ok_or(Error::Capacity)
    })?;
    if size > limit {
        return Err(Error::Capacity);
    }
    for part in parts {
        output.extend_from_slice(part);
    }
    Ok(())
}

#[cfg(test)]
#[path = "suid_path_tests.rs"]
mod suid_path_tests;

fn copy_io_error(error: &std::io::Error) -> std::io::Error {
    error.raw_os_error().map_or_else(
        || std::io::Error::new(error.kind(), error.to_string()),
        std::io::Error::from_raw_os_error,
    )
}
