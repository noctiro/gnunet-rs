//! Configuration-tool operations shared by the official command-line frontend.
use crate::{
    Configuration, Environment, Error, ProcessEnvironment, UTIL_VERSION, bytes_path, path_bytes,
};
use std::path::Path;
/// Owned counterpart of the complete public configuration-tool settings struct.
#[derive(Clone, Debug)]
pub struct ConfigSettings {
    /// Selected utility API version. The C backend itself does not validate it.
    pub api_version: u32,
    /// Section to query or set.
    pub section: Option<Vec<u8>>,
    /// Option to query or set.
    pub option: Option<Vec<u8>>,
    /// New raw value.
    pub value: Option<Vec<u8>>,
    /// Interpret returned values as filenames.
    pub is_filename: bool,
    /// List visible section names.
    pub list_sections: bool,
    /// Rewrite even without setting a value.
    pub rewrite: bool,
    /// Zero disables diagnostics, one shows effective sources, two all sources.
    pub diagnostics: u32,
    /// Write the full configuration instead of its difference from defaults.
    pub full: bool,
    /// Initial command result, matching the caller-owned C field.
    pub global_ret: i32,
}
impl Default for ConfigSettings {
    fn default() -> Self {
        Self {
            api_version: UTIL_VERSION,
            section: None,
            option: None,
            value: None,
            is_filename: false,
            list_sections: false,
            rewrite: false,
            diagnostics: 0,
            full: false,
            global_ret: 0,
        }
    }
}
impl ConfigSettings {
    /// Release the three owned option strings, corresponding to settings_free.
    pub fn clear_strings(&mut self) {
        self.section = None;
        self.option = None;
        self.value = None;
    }
}
/// Explicit command output and exit status. Byte output preserves non-UTF-8
/// values and can be written by a CLI without hidden printing from the library.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutput {
    /// Normal command output.
    pub stdout: Vec<u8>,
    /// User-facing diagnostics, separate from raw configuration values.
    pub stderr: Vec<u8>,
    /// Official command result (0 success, 2 invalid/write, 6 missing value).
    pub exit_code: i32,
}
/// One actual tool result and its independently retained configuration failure.
/// A source-defined nonzero output status does not erase the original I/O error.
#[derive(Debug)]
pub struct ToolReport {
    /// Unchanged functional output and source result code.
    pub output: ToolOutput,
    /// Original error folded into a source-defined output status, when present.
    pub error: Option<Error>,
}
impl Configuration {
    /// Perform official config_tool_run operations. Successful setters rewrite
    /// using a temporary duplicate; the original configuration remains owned by
    /// its caller. File I/O failures are reported by an explicit nonzero status.
    pub fn run_tool(
        &self,
        settings: &ConfigSettings,
        cfgfile: Option<&Path>,
    ) -> Result<ToolOutput, Error> {
        self.run_tool_report_observed(settings, cfgfile, None)
            .map(|report| report.output)
    }
    /// Execute with the original synchronous diagnostic route. A local observer
    /// replaces persistent observation for nested loads, lookups and rewrites.
    /// Configuration and diagnostic errors remain independently reportable by
    /// the caller; the observer cannot replace a source result with success.
    pub fn run_tool_report_observed(
        &self,
        settings: &ConfigSettings,
        cfgfile: Option<&Path>,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<ToolReport, Error> {
        let mut reloaded = None;
        if settings.diagnostics > 0 && !self.diagnostics_enabled() {
            let mut cfg = self.fresh()?;
            cfg.enable_diagnostics();
            cfg.load_observed(cfgfile, observer)?;
            reloaded = Some(cfg);
        }
        let cfg = reloaded.as_ref().unwrap_or(self);
        let limit = cfg.limits.max_expanded_bytes;
        let mut out = ToolOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: settings.global_ret,
        };
        let mut failure = None;
        let rewrite = settings.rewrite || settings.full;
        if settings.list_sections {
            crate::configuration::text(
                &mut out.stderr,
                limit,
                &[b"The following sections are available:\n"],
            )?;
            for section in cfg.sections() {
                crate::configuration::text(&mut out.stdout, limit, &[section.name()])?;
                crate::configuration::text(&mut out.stdout, limit, &[b"\n"])?;
            }
            return Ok(ToolReport {
                output: out,
                error: None,
            });
        }
        if !rewrite && settings.section.is_none() {
            if settings.diagnostics == 0 {
                out.exit_code = 2;
                crate::configuration::text(
                    &mut out.stderr,
                    limit,
                    &[b"--section, --list-sections or --diagnostics argument is required\n"],
                )?;
                return Ok(ToolReport {
                    output: out,
                    error: None,
                });
            }
            out.stdout = if settings.diagnostics > 1 {
                cfg.serialize_diagnostics_verbose()?
            } else {
                cfg.serialize_diagnostics()?
            };
            return Ok(ToolReport {
                output: out,
                error: None,
            });
        }
        let mut changed = None;
        if let Some(section) = settings.section.as_deref() {
            if let Some(value) = settings.value.as_deref() {
                let Some(option) = settings.option.as_deref() else {
                    out.exit_code = 2;
                    crate::configuration::text(
                        &mut out.stderr,
                        limit,
                        &[b"--option argument required to set value\n"],
                    )?;
                    return Ok(ToolReport {
                        output: out,
                        error: None,
                    });
                };
                let mut copy = cfg.duplicate()?;
                copy.set_value_observed(section, option, Some(value), observer)?;
                changed = Some(copy);
            } else if let Some(option) = settings.option.as_deref() {
                if settings.is_filename {
                    match cfg.get_filename_observed(section, option, &ProcessEnvironment, observer)
                    {
                        Ok(path) => crate::configuration::text(
                            &mut out.stdout,
                            limit,
                            &[path_bytes(&path)?],
                        )?,
                        Err(Error::Missing) => {
                            out.exit_code = 6;
                            return Ok(ToolReport {
                                output: out,
                                error: None,
                            });
                        }
                        Err(error) => return Err(error),
                    }
                } else if let Some(value) = cfg.get_observed(section, option, observer) {
                    crate::configuration::text(&mut out.stdout, limit, &[value])?;
                } else {
                    out.exit_code = 6;
                    return Ok(ToolReport {
                        output: out,
                        error: None,
                    });
                }
                crate::configuration::text(&mut out.stdout, limit, &[b"\n"])?;
            } else {
                for (_, option, value) in cfg.section_values_observed(section, observer) {
                    crate::configuration::text(&mut out.stdout, limit, &[option])?;
                    crate::configuration::text(&mut out.stdout, limit, &[b" = "])?;
                    if settings.is_filename {
                        crate::configuration::text(
                            &mut out.stdout,
                            limit,
                            &[path_bytes(&cfg.get_filename_observed(
                                section,
                                option,
                                &ProcessEnvironment,
                                observer,
                            )?)?],
                        )?;
                    } else {
                        crate::configuration::text(&mut out.stdout, limit, &[value])?;
                    }
                    crate::configuration::text(&mut out.stdout, limit, &[b"\n"])?;
                }
            }
        }
        if rewrite || changed.is_some() {
            let owned_path = if cfgfile.is_none() {
                let raw = if let Some(mut xdg) = ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
                    xdg.push(b'/');
                    xdg.extend_from_slice(&cfg.project_data().config_file);
                    xdg
                } else {
                    cfg.project_data().user_config_file.clone()
                };
                Some(bytes_path(&raw)?)
            } else {
                None
            };
            let path = cfgfile.or(owned_path.as_deref()).ok_or(Error::Missing)?;
            let mut copy = if let Some(copy) = changed {
                copy
            } else {
                cfg.duplicate()?
            };
            let result = if settings.full {
                copy.write_observed(path, observer)
            } else {
                let mut defaults = cfg.fresh()?;
                match defaults.load_observed(None, observer) {
                    Ok(()) => defaults.write_diffs_observed(&copy, path, observer),
                    Err(error) => {
                        out.exit_code = 1;
                        crate::configuration::text(
                            &mut out.stderr,
                            limit,
                            &[b"failed to load configuration defaults\n"],
                        )?;
                        return if matches!(error, Error::Capacity) {
                            Err(error)
                        } else {
                            Ok(ToolReport {
                                output: out,
                                error: Some(error),
                            })
                        };
                    }
                }
            };
            if let Err(error) = result {
                if matches!(error, Error::Capacity) {
                    return Err(error);
                }
                out.exit_code = 2;
                crate::configuration::text(
                    &mut out.stderr,
                    limit,
                    &[b"failed to write configuration\n"],
                )?;
                failure = Some(error);
            }
        }
        Ok(ToolReport {
            output: out,
            error: failure,
        })
    }
}
