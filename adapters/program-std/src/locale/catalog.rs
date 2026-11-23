//! Owned GNU gettext message catalogs for ordinary Rust commands and services.
mod mo;
mod plural;
#[cfg(test)]
mod tests;

use super::{Translations, disabled, prefix};
use crate::program::{Failure, LocaleSetup};
use gnunet_config::{Installation, PathKind, ProcessEnvironment, ProjectData};
use std::{
    cell::RefCell,
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    rc::Rc,
};

const MAX_LANGUAGES: usize = 12;
const MAX_LOCALE_BYTES: usize = 128;
const MAX_DOMAINS: usize = 8;
const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

/// Standard locale preferences and installed UTF-8 GNU message catalogs.
/// The host reads catalog data without changing process-wide C locale state.
pub struct InstalledLocale {
    translations: Rc<dyn Translations>,
}

impl Default for InstalledLocale {
    fn default() -> Self {
        Self {
            translations: disabled(),
        }
    }
}

impl LocaleSetup for InstalledLocale {
    fn configure(&mut self, project: &ProjectData) -> Result<(), Failure> {
        self.translations = translations(project)?;
        Ok(())
    }

    fn translations(&self) -> Rc<dyn Translations> {
        Rc::clone(&self.translations)
    }

    fn case_context(&self) -> Option<gnunet_config::CaseContext> {
        None
    }
}

pub(crate) fn translations(project: &ProjectData) -> Result<Rc<dyn Translations>, Failure> {
    let Some(domain) = project.gettext_domain.as_deref() else {
        return Ok(disabled());
    };
    let names = preferences(|key| env::var(key).ok())?;
    if names.is_empty() {
        return Ok(disabled());
    }
    let directory = match &project.gettext_path {
        Some(path) => Some(path.clone()),
        None => Installation::discover(project, &ProcessEnvironment)?
            .path(PathKind::Localedir)
            .map(Path::to_path_buf),
    };
    let Some(directory) = directory else {
        return Ok(disabled());
    };
    let domain = checked_component(domain)?.to_owned();
    let selected = Installed {
        domain,
        directory,
        names,
        loaded: RefCell::new(Vec::new()),
    };
    // Validate and retain the main domain at PROGRAM/SERVICE setup. Optional
    // domains are loaded on their first actual lookup under the same limits.
    selected.with_domain(None, |_| ())?;
    Ok(Rc::new(selected))
}

fn source_locale(locale: &str) -> bool {
    matches!(locale, "C" | "POSIX")
}

fn checked_component(value: &[u8]) -> io::Result<&str> {
    if value.is_empty()
        || value.len() > MAX_LOCALE_BYTES
        || !value.first().is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid gettext locale or domain component",
        ));
    }
    std::str::from_utf8(value).map_err(io::Error::other)
}

fn preferences(read: impl Fn(&str) -> Option<String>) -> io::Result<Vec<String>> {
    let selected = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(&read)
        .find(|value| !value.is_empty());
    let Some(selected) = selected.filter(|locale| !source_locale(locale)) else {
        return Ok(Vec::new());
    };
    let list = read("LANGUAGE")
        .filter(|value| !value.is_empty())
        .unwrap_or(selected);
    if list.len() > MAX_LANGUAGES * MAX_LOCALE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gettext language list exceeds its bounds",
        ));
    }
    let mut names = Vec::new();
    for (index, name) in list
        .split(':')
        .filter(|value| !value.is_empty())
        .enumerate()
    {
        if source_locale(name) {
            break;
        }
        if index == MAX_LANGUAGES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many gettext languages",
            ));
        }
        checked_component(name.as_bytes())?;
        add_variants(name, &mut names);
    }
    Ok(names)
}

fn add_variants(name: &str, names: &mut Vec<String>) {
    let (base, modifier) = name.split_once('@').unwrap_or((name, ""));
    let (base, codeset) = base.split_once('.').unwrap_or((base, ""));
    let (language, territory) = base.split_once('_').unwrap_or((base, ""));
    let mut normalized: String = codeset
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    if !normalized.is_empty() && normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        normalized.insert_str(0, "iso");
    }
    for modifier in [modifier, ""] {
        for territory in [territory, ""] {
            for codeset in [codeset, normalized.as_str(), ""] {
                let mut variant = language.to_owned();
                for (delimiter, value) in [('_', territory), ('.', codeset), ('@', modifier)] {
                    if !value.is_empty() {
                        variant.push(delimiter);
                        variant.push_str(value);
                    }
                }
                if !names.contains(&variant) {
                    names.push(variant);
                }
            }
        }
    }
}

struct Domain {
    name: String,
    catalogs: Vec<mo::Catalog>,
}

struct Installed {
    domain: String,
    directory: PathBuf,
    names: Vec<String>,
    loaded: RefCell<Vec<Domain>>,
}

impl Installed {
    fn with_domain<R>(
        &self,
        domain: Option<&[u8]>,
        read: impl FnOnce(&[mo::Catalog]) -> R,
    ) -> io::Result<R> {
        let domain = domain
            .map(checked_component)
            .transpose()?
            .unwrap_or(&self.domain);
        let mut loaded = self.loaded.borrow_mut();
        if let Some(original) = loaded.iter().find(|entry| entry.name == domain) {
            return Ok(read(&original.catalogs));
        }
        if loaded.len() == MAX_DOMAINS {
            return Err(io::Error::other("gettext domain capacity exhausted"));
        }
        let retained = loaded
            .iter()
            .flat_map(|entry| &entry.catalogs)
            .map(mo::Catalog::len)
            .sum();
        let catalogs = self.load_domain(domain, retained)?;
        let value = read(&catalogs);
        loaded.push(Domain {
            name: domain.to_owned(),
            catalogs,
        });
        Ok(value)
    }

    fn load_domain(&self, domain: &str, mut retained: usize) -> io::Result<Vec<mo::Catalog>> {
        let filename = format!("{domain}.mo");
        let mut catalogs = Vec::new();
        for locale in &self.names {
            let path = self
                .directory
                .join(locale)
                .join("LC_MESSAGES")
                .join(&filename);
            let file = match open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let limit = (MAX_TOTAL_BYTES - retained).min(MAX_CATALOG_BYTES);
            let mut bytes = Vec::new();
            file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
            if bytes.len() > limit {
                return Err(io::Error::other("gettext catalog capacity exhausted"));
            }
            let catalog = mo::Catalog::parse(bytes)?;
            retained += catalog.len();
            if retained > MAX_TOTAL_BYTES {
                return Err(io::Error::other("gettext catalog capacity exhausted"));
            }
            catalogs.push(catalog);
        }
        Ok(catalogs)
    }
}

fn open(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        gnunet_native::paths::open_regular_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a regular gettext catalog",
            ));
        }
        Ok(file)
    }
}

impl Translations for Installed {
    fn gettext(&self, domain: Option<&[u8]>, message: &[u8]) -> io::Result<Vec<u8>> {
        let message = prefix(message);
        self.with_domain(domain, |catalogs| {
            catalogs
                .iter()
                .find_map(|catalog| catalog.message(message, None))
                .unwrap_or(message)
                .to_vec()
        })
    }

    fn ngettext(
        &self,
        domain: Option<&[u8]>,
        singular: &[u8],
        plural: &[u8],
        count: u64,
    ) -> io::Result<Vec<u8>> {
        let singular = prefix(singular);
        self.with_domain(domain, |catalogs| {
            catalogs
                .iter()
                .find_map(|catalog| catalog.message(singular, Some(count)))
                .unwrap_or_else(|| if count == 1 { singular } else { prefix(plural) })
                .to_vec()
        })
    }
}
