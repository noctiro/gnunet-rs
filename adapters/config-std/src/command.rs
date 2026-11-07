//! Official configuration frontend syntax and explicit host capability checks.
use crate::{
    ConfigSettings, Configuration, Error, Installation, Limits, PathKind, ProcessEnvironment,
    ProjectData, ToolOutput, bytes_path, path_bytes,
};
use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Default)]
struct Command {
    settings: ConfigSettings,
    file: Option<PathBuf>,
    no_defaults: bool,
    ram: Option<Vec<u8>>,
    clean: bool,
    prefix: bool,
    cflags: bool,
    libs: bool,
    experimental: bool,
    backend: Option<Vec<u8>>,
    help: bool,
    version: bool,
    loglevel: Option<Vec<u8>>,
    logfile: Option<PathBuf>,
    positional: Vec<Vec<u8>>,
    option_count: usize,
}
fn value(
    arguments: &[Vec<u8>],
    index: &mut usize,
    attached: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    if let Some(value) = attached {
        return Ok(value);
    }
    *index += 1;
    arguments.get(*index).cloned().ok_or(Error::InvalidInput)
}
impl Command {
    fn parse(arguments: &[OsString]) -> Result<Self, Error> {
        let args: Vec<_> = arguments
            .iter()
            .map(|v| path_bytes(Path::new(v)).map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let mut out = Self::default();
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if arg == b"--" {
                out.positional.extend_from_slice(&args[index + 1..]);
                break;
            }
            if arg.starts_with(b"--") {
                let split = arg.iter().position(|b| *b == b'=');
                let name = &arg[2..split.unwrap_or(arg.len())];
                let attached = split.map(|i| arg[i + 1..].to_vec());
                let short = match name {
                    b"config" => b'c',
                    b"full" => b'F',
                    b"filename" => b'f',
                    b"option" => b'o',
                    b"rewrite" => b'r',
                    b"diagnostics" => b'd',
                    b"list-sections" => b'S',
                    b"section" => b's',
                    b"value" => b'V',
                    b"clean" => b'x',
                    b"no-defaults" => b'n',
                    b"ram-config" => b'R',
                    b"prefix" => b'p',
                    b"cflags" => b'C',
                    b"libs" => b'j',
                    b"is-experimental" => b'E',
                    b"supported-backend" => b'b',
                    b"help" => b'h',
                    b"version" => b'v',
                    b"log" => b'L',
                    b"logfile" => b'l',
                    _ => return Err(Error::InvalidInput),
                };
                out.option(short, attached, &args, &mut index)?;
            } else if arg.starts_with(b"-") && arg.len() > 1 {
                let mut offset = 1;
                while offset < arg.len() {
                    let option = arg[offset];
                    let needs = matches!(
                        option,
                        b'c' | b'o' | b's' | b'V' | b'R' | b'b' | b'L' | b'l'
                    );
                    let attached = if needs && offset + 1 < arg.len() {
                        Some(arg[offset + 1..].to_vec())
                    } else {
                        None
                    };
                    out.option(option, attached, &args, &mut index)?;
                    if needs {
                        break;
                    }
                    offset += 1;
                }
            } else {
                out.positional.push(arg.clone());
            }
            index += 1;
        }
        Ok(out)
    }
    fn option(
        &mut self,
        option: u8,
        attached: Option<Vec<u8>>,
        args: &[Vec<u8>],
        index: &mut usize,
    ) -> Result<(), Error> {
        self.option_count = self.option_count.checked_add(1).ok_or(Error::Capacity)?;
        if !matches!(
            option,
            b'c' | b'o' | b's' | b'V' | b'R' | b'b' | b'L' | b'l'
        ) && attached.is_some()
        {
            return Err(Error::InvalidInput);
        }
        match option {
            b'c' => self.file = Some(bytes_path(&value(args, index, attached)?)?),
            b'o' => self.settings.option = Some(value(args, index, attached)?),
            b's' => self.settings.section = Some(value(args, index, attached)?),
            b'V' => self.settings.value = Some(value(args, index, attached)?),
            b'R' => self.ram = Some(value(args, index, attached)?),
            b'b' => self.backend = Some(value(args, index, attached)?),
            b'L' => self.loglevel = Some(value(args, index, attached)?),
            b'l' => self.logfile = Some(bytes_path(&value(args, index, attached)?)?),
            b'F' => self.settings.full = true,
            b'f' => self.settings.is_filename = true,
            b'r' => self.settings.rewrite = true,
            b'd' => {
                self.settings.diagnostics = self
                    .settings
                    .diagnostics
                    .checked_add(1)
                    .ok_or(Error::Capacity)?
            }
            b'S' => self.settings.list_sections = true,
            b'x' => self.clean = true,
            b'n' => self.no_defaults = true,
            b'p' => self.prefix = true,
            b'C' => self.cflags = true,
            b'j' => self.libs = true,
            b'E' => self.experimental = true,
            b'h' => self.help = true,
            b'v' => self.version = true,
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }
}
/// Parsed logging selection, without installing a logger or opening a file.
#[derive(Clone, Copy)]
pub struct ConfigCommandLogging<'a> {
    /// Requested generic log threshold; None selects the logger's default.
    pub level: Option<&'a [u8]>,
    /// Requested log filename, before native logger template expansion.
    pub file: Option<&'a Path>,
}
/// Immediate parser output or a command awaiting its explicit logging owner.
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded parsed command remains directly owned; preparation adds no separate heap allocation"
)]
pub enum ConfigCommandPreparation {
    /// Help, argument failure or an exclusive-option conflict; no command IO.
    Immediate(ToolOutput),
    /// Actual command data. Select logging before executing this value.
    Ready(PreparedConfigCommand),
}
/// Owned configuration command. Its private fields preserve one parse and the
/// original version-prefix/output bytes across explicit logging selection.
pub struct PreparedConfigCommand {
    command: Command,
    output: ToolOutput,
    project: Arc<ProjectData>,
}
impl PreparedConfigCommand {
    /// Borrow the exact requested logging values; performs no filesystem IO.
    pub fn logging(&self) -> ConfigCommandLogging<'_> {
        ConfigCommandLogging {
            level: self.command.loglevel.as_deref(),
            file: self.command.logfile.as_deref(),
        }
    }
    /// Already prepared functional bytes, retained if logging setup refuses.
    pub fn initial_output(&self) -> &ToolOutput {
        &self.output
    }
    /// Execute an embedding call without a logging owner. Explicit non-ERROR or
    /// file logging needs the observed path instead of being silently ignored.
    pub fn execute(self) -> Result<ToolOutput, Error> {
        if self.command.logfile.is_some()
            || self
                .command
                .loglevel
                .as_deref()
                .is_some_and(|v| !v.eq_ignore_ascii_case(b"ERROR"))
        {
            return Err(Error::Unsupported);
        }
        self.run(None).map(|report| report.output)
    }
    /// Execute after the caller selected the actual logging owner. The borrowed
    /// route covers configuration reads, nested files, typed lookups and writes;
    /// it is never stored in the Configuration or returned command result.
    pub fn execute_observed(
        self,
        observer: crate::diagnostic::BorrowedObserver<'_>,
    ) -> Result<crate::ToolReport, Error> {
        self.run(Some(observer))
    }
    fn run(
        self,
        observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<crate::ToolReport, Error> {
        let Self {
            command,
            mut output,
            project,
        } = self;
        if command.clean
            && (command.ram.is_some()
                || command.backend.is_some()
                || command.cflags
                || command.experimental
                || command.libs
                || command.prefix
                || command.settings.full
                || command.settings.is_filename
                || command.settings.option.is_some()
                || command.settings.rewrite
                || command.settings.diagnostics != 0
                || command.settings.list_sections
                || command.settings.section.is_some()
                || command.settings.value.is_some()
                || !command.positional.is_empty())
        {
            output.exit_code = 2;
            output.stderr=b"--clean requires a file-backed configuration and cannot be combined with another operation\n".to_vec();
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        // The normal v0.29.1 header defines the macro to zero, but its frontend
        // uses ifdef. This is source-profile metadata, not a feature certificate.
        if command.experimental {
            output.exit_code = i32::from(!crate::OFFICIAL_BUILD_PROFILE.experimental_macro_defined);
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        if command.backend.is_some() {
            // No Rust backend registry is selected by this frontend. Keep the
            // explicit skip status; a C plugin's presence is not Rust support.
            output.exit_code = 77;
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        if command.prefix || command.cflags || command.libs {
            let installation = Installation::discover(&project, &ProcessEnvironment)?;
            let prefix = installation.path(PathKind::Prefix).ok_or(Error::Missing)?;
            let libdir = installation.path(PathKind::Libdir).ok_or(Error::Missing)?;
            if command.cflags || command.libs {
                // A Rust SDK does not imply a C ABI development package. Report
                // these flags only when the actual headers/library are installed.
                let headers = prefix.join("include/gnunet_util_lib.h");
                let library = fs::read_dir(libdir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .as_encoded_bytes()
                            .starts_with(b"libgnunetutil.")
                    });
                if !headers.is_file() || !library {
                    return Err(Error::Unsupported);
                }
            }
            if command.cflags {
                output.stdout.extend_from_slice(b"-I");
                output.stdout.extend_from_slice(path_bytes(prefix)?);
                output.stdout.extend_from_slice(b"include\n");
            }
            if command.libs {
                output.stdout.extend_from_slice(b"-L");
                output.stdout.extend_from_slice(path_bytes(libdir)?);
                output.stdout.extend_from_slice(b" -lgnunetutil\n");
            }
            if command.prefix {
                output.stdout.extend_from_slice(path_bytes(prefix)?);
                output.stdout.push(b'\n');
            }
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        let filename = match command.file {
            Some(file) => Some(file),
            None => project.default_filename(&ProcessEnvironment)?,
        };
        if command.clean && filename.is_none() {
            output.exit_code = 2;
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        let mut configuration = Configuration::create(project, Limits::default())?;
        if command.settings.diagnostics != 0 || command.clean {
            configuration.enable_diagnostics();
        }
        let loaded = if let Some(ram) = command.ram {
            if !command.no_defaults {
                configuration.load_observed(None, observer)?;
            }
            configuration.deserialize_observed(&ram, None, observer)
        } else if let Some(filename) = filename.as_deref() {
            if command.no_defaults {
                configuration.parse_observed(filename, &ProcessEnvironment, observer)
            } else {
                configuration.load_observed(Some(filename), observer)
            }
        } else if command.no_defaults {
            Ok(())
        } else {
            configuration.load_observed(None, observer)
        };
        if let Err(error) = loaded {
            if matches!(error, Error::Capacity) {
                return Err(error);
            }
            output.exit_code = 1;
            output.stderr = b"failed to load configuration\n".to_vec();
            return Ok(crate::ToolReport {
                output,
                error: Some(error),
            });
        }
        if command.clean {
            let filename = filename.as_deref().ok_or(Error::Missing)?;
            let mut records = Vec::new();
            let removed = configuration
                .clean_file_with_observed(filename, observer, |line| records.push(line.clone()))?;
            for line in records {
                output.stdout.extend_from_slice(b"Removed [");
                output.stdout.extend_from_slice(&line.section);
                output.stdout.extend_from_slice(b"]/");
                output.stdout.extend_from_slice(&line.option);
                output.stdout.extend_from_slice(b" at ");
                output.stdout.extend_from_slice(path_bytes(filename)?);
                output
                    .stdout
                    .extend_from_slice(format!(":{}\n", line.line).as_bytes());
            }
            output.stdout.extend_from_slice(
                format!(
                    "Removed {removed} duplicate definition{} from ",
                    if removed == 1 { "" } else { "s" }
                )
                .as_bytes(),
            );
            output.stdout.extend_from_slice(path_bytes(filename)?);
            output.stdout.push(b'\n');
            return Ok(crate::ToolReport {
                output,
                error: None,
            });
        }
        let mut result = configuration.run_tool_report_observed(
            &command.settings,
            filename.as_deref(),
            observer,
        )?;
        if !output.stdout.is_empty() {
            output.stdout.extend_from_slice(&result.output.stdout);
            result.output.stdout = output.stdout;
        }
        Ok(result)
    }
}
/// Execute configuration arguments without a selected generic logging owner.
/// The ordinary binary uses the ProgramHost selected-logging composition.
pub fn run_config_command(arguments: &[OsString]) -> Result<ToolOutput, Error> {
    run_config_command_with_program(OsStr::new("gnunet-config"), arguments)
}
/// Unobserved embedding helper, retaining the actual argv0 help/version bytes.
pub fn run_config_command_with_program(
    program: &OsStr,
    arguments: &[OsString],
) -> Result<ToolOutput, Error> {
    match prepare_config_command_with_program(program, arguments)? {
        ConfigCommandPreparation::Immediate(output) => Ok(output),
        ConfigCommandPreparation::Ready(command) => command.execute(),
    }
}
/// Parse and preserve immediate command rules before selecting a logging owner.
/// No configuration file is read or rewritten by this preparation step.
pub fn prepare_config_command_with_program(
    program: &OsStr,
    arguments: &[OsString],
) -> Result<ConfigCommandPreparation, Error> {
    let command = match Command::parse(arguments) {
        Ok(value) => value,
        Err(Error::InvalidInput) => {
            return Ok(ConfigCommandPreparation::Immediate(ToolOutput {
                stdout: Vec::new(),
                stderr: b"invalid gnunet-config arguments\n".to_vec(),
                exit_code: 2,
            }));
        }
        Err(error) => return Err(error),
    };
    let mut output = ToolOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_code: 0,
    };
    let backend_conflict = command.backend.is_some() && command.option_count > 1;
    if command.help {
        output.stdout=b"Usage: gnunet-config [OPTIONS]\n  -c, --config FILE\n  -s, --section SECTION  -o, --option OPTION  -V, --value VALUE\n  -F, --full  -f, --filename  -r, --rewrite  -d, --diagnostics\n  -S, --list-sections  -x, --clean  -n, --no-defaults\n  -R, --ram-config CONFIG  -p, --prefix  -C, --cflags  -j, --libs\n  -E, --is-experimental  -b, --supported-backend BACKEND\n".to_vec();
        if backend_conflict {
            output.exit_code = 2;
            output.stderr =
                b"Option `supported-backend' can't be used with other options.\n".to_vec();
        }
        return Ok(ConfigCommandPreparation::Immediate(output));
    }
    let project = Arc::new(ProjectData::default());
    if command.version {
        output.stdout = path_bytes(Path::new(program))?.to_vec();
        output.stdout.extend_from_slice(b" v");
        output.stdout.extend_from_slice(&project.version);
        output.stdout.push(b'\n');
        if command.option_count > 1 {
            output.exit_code = 2;
            output
                .stderr
                .extend_from_slice(b"Option `version' can't be used with other options.\n");
            return Ok(ConfigCommandPreparation::Immediate(output));
        }
        // The pinned gnunet-config main does not stop when GETOPT's version
        // callback returns NO: it still loads defaults and runs the backend.
    }
    // Keep the already emitted version/help output before reporting an
    // exclusive-option conflict, as the official frontend does. Positional
    // arguments are not additional options; repeated backend options are.
    if backend_conflict {
        output.exit_code = 2;
        output.stderr = b"Option `supported-backend' can't be used with other options.\n".to_vec();
        return Ok(ConfigCommandPreparation::Immediate(output));
    }
    Ok(ConfigCommandPreparation::Ready(PreparedConfigCommand {
        command,
        output,
        project,
    }))
}
