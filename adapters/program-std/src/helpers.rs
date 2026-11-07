//! Safe owned counterparts of the official GETOPT helper factories.
use crate::format::Argument as Value;
use crate::getopt::{Argument, Context, Definition, Output, Spec};
use gnunet_types::Error;
use std::{cell::RefCell, path::PathBuf, rc::Rc};
/// Shared caller-owned destination. Cloning shares the same object; it never
/// clones the destination data or grants a mutable borrow across processing.
pub struct Target<T>(Rc<RefCell<T>>);
impl<T> Clone for Target<T> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}
impl<T> Target<T> {
    /// Create a destination with its caller-selected initial value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(Rc::new(RefCell::new(value)))
    }
    /// Read an owned copy, only when the destination type explicitly permits Clone.
    pub fn get(&self) -> Result<T, Error>
    where
        T: Clone,
    {
        self.0
            .try_borrow()
            .map(|v| v.clone())
            .map_err(|_| Error::Conflict)
    }
    /// Inspect synchronously; borrowed data cannot escape through this closure.
    pub fn with<R>(&self, read: impl FnOnce(&T) -> R) -> Result<R, Error> {
        self.0
            .try_borrow()
            .map(|v| read(&v))
            .map_err(|_| Error::Conflict)
    }
    fn update<R>(&self, write: impl FnOnce(&mut T) -> R) -> Result<R, Error> {
        self.0
            .try_borrow_mut()
            .map(|mut v| write(&mut v))
            .map_err(|_| Error::Conflict)
    }
}
/// Filename helper outcome. The source returns OK even when expansion yields
/// NULL; the explicit failure record must be routed by the owning PROGRAM layer.
#[derive(Clone, Debug)]
pub struct Filename {
    /// Expanded native path, or original C NULL outcome.
    pub path: Option<PathBuf>,
    /// Typed expansion failure, never fabricated success.
    pub error: Option<Rc<gnunet_config::Error>>,
}
fn spec<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: Option<&'a [u8]>,
    description: &'a [u8],
    argument: Argument,
) -> Spec<'a> {
    Spec {
        short,
        name,
        argument_help,
        description: Some(description),
        argument,
        mandatory: false,
        exclusive: false,
    }
}
/// Source flag sets signed int to1, independent of any previous value.
pub fn flag<'a>(
    short: u8,
    name: &'a [u8],
    description: &'a [u8],
    target: Target<i32>,
) -> Definition<'a> {
    Definition::new(
        spec(short, name, None, description, Argument::None),
        move |_: Context<'_>, _: &[u8], _: Option<&[u8]>, _: &mut Output| {
            if target.update(|v| *v = 1).is_ok() {
                1
            } else {
                -1
            }
        },
    )
}
/// Source unsigned increment wraps at UINT32_MAX.
pub fn increment<'a>(
    short: u8,
    name: &'a [u8],
    description: &'a [u8],
    target: Target<u32>,
) -> Definition<'a> {
    Definition::new(
        spec(short, name, None, description, Argument::None),
        move |_: Context<'_>, _: &[u8], _: Option<&[u8]>, _: &mut Output| {
            if target.update(|v| *v = v.wrapping_add(1)).is_ok() {
                1
            } else {
                -1
            }
        },
    )
}
/// Standard -V/--verbose helper.
pub fn verbose(target: Target<u32>) -> Definition<'static> {
    increment(b'V', b"verbose", b"be verbose", target)
}
/// Source string replacement retains all native value bytes before the C NUL.
pub fn string<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<Option<Vec<u8>>>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, _: &[u8], value: Option<&[u8]>, _: &mut Output| {
            let Some(value) = value else {
                return -1;
            };
            if target.update(|v| *v = Some(value.to_vec())).is_ok() {
                1
            } else {
                -1
            }
        },
    )
}
/// Source filename expansion uses only HOME/current directory/PWD, not dollar
/// PATHS substitution. It reports the source NULL outcome without inventing a path.
pub fn filename<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<Filename>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, _: &[u8], value: Option<&[u8]>, output: &mut Output| {
            let Some(value) = value else {
                return -1;
            };
            // GNUNET_free(*val) clears the target before filename_expand can
            // invoke logging callbacks. Observers must never see the prior path.
            if target
                .update(|value| {
                    *value = Filename {
                        path: None,
                        error: None,
                    }
                })
                .is_err()
            {
                return -1;
            }
            let (path, error) = match gnunet_config::Configuration::default()
                .expand_filename_observed(
                    value,
                    &gnunet_config::ProcessEnvironment,
                    output.configuration_observer(),
                ) {
                Ok(path) => (Some(path), None),
                Err(error) => (None, Some(Rc::new(error))),
            };
            if target.update(|v| *v = Filename { path, error }).is_ok() {
                1
            } else {
                -1
            }
        },
    )
}
/// Standard -c/--config helper.
pub fn cfgfile(target: Target<Filename>) -> Definition<'static> {
    filename(
        b'c',
        b"config",
        b"FILENAME",
        b"use configuration file FILENAME",
        target,
    )
}
/// Standard -l/--logfile helper.
pub fn logfile(target: Target<Filename>) -> Definition<'static> {
    filename(
        b'l',
        b"logfile",
        b"FILENAME",
        b"configure logging to write logs to FILENAME",
        target,
    )
}
/// Standard -L/--log helper; source accepts an arbitrary string without validation.
pub fn loglevel(target: Target<Option<Vec<u8>>>) -> Definition<'static> {
    string(
        b'L',
        b"log",
        b"LOGLEVEL",
        b"configure logging to use LOGLEVEL",
        target,
    )
}
/// Standard exclusive -v/--version, using actual `argv[0]`, not binaryOptions.
pub fn version(version: &[u8]) -> Definition<'_> {
    Definition::new(
        spec(
            b'v',
            b"version",
            None,
            b"print the version number",
            Argument::None,
        ),
        move |ctx: Context<'_>, _: &[u8], _: Option<&[u8]>, out: &mut Output| {
            out.stdout.extend_from_slice(ctx.binary_name);
            out.stdout.extend_from_slice(b" v");
            out.stdout.extend_from_slice(prefix(version));
            out.stdout.push(b'\n');
            0
        },
    )
    .exclusive()
}
/// Standard exclusive English/C-locale help. Full catalog translation is a
/// required separate locale adapter, not silently claimed by this formatter.
pub fn help<'a>(
    project: &'a gnunet_config::ProjectData,
    about: Option<&'a [u8]>,
) -> Definition<'a> {
    Definition::new(
        spec(b'h', b"help", about, b"print this help", Argument::None),
        move |ctx: Context<'_>, _: &[u8], _: Option<&[u8]>, out: &mut Output| {
            let translations = out.translations();
            match format_help(ctx, project, translations.as_ref(), &mut out.stdout) {
                Ok(()) => 0,
                Err(error) => {
                    out.failure = Some(error);
                    -1
                }
            }
        },
    )
    .exclusive()
}
fn format_help(
    ctx: Context<'_>,
    project: &gnunet_config::ProjectData,
    translations: &dyn crate::locale::Translations,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    let options = ctx
        .options
        .iter()
        .take_while(|opt| opt.description.is_some())
        .collect::<Vec<_>>();
    if let Some(about) = options
        .iter()
        .filter(|opt| opt.short == b'h')
        .filter_map(|opt| opt.argument_help)
        .next_back()
    {
        out.extend_from_slice(ctx.binary_options);
        out.push(b'\n');
        out.extend_from_slice(&translations.gettext(None, about)?);
        out.push(b'\n');
        out.extend_from_slice(&translations.gettext(
            Some(b"gnunet"),
            b"Arguments mandatory for long options are also mandatory for short options.\n",
        )?);
    }
    for option in options {
        if option.short == 0 {
            out.extend_from_slice(b"      ");
        } else {
            out.extend_from_slice(b"  -");
            out.push(option.short);
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(option.name);
        let mut length = 8 + option.name.len();
        if let Some(argument) = option.argument_help
            && option.short != b'h'
        {
            out.push(b'=');
            out.extend_from_slice(argument);
            length += 1 + argument.len();
        }
        if length > 29 {
            out.push(b'\n');
            out.extend_from_slice(&[b' '; 29]);
            length = 29;
        }
        if length < 29 {
            out.extend(std::iter::repeat_n(b' ', 29 - length));
            length = 29;
        }
        let original = option.description.unwrap_or_default();
        let translated = if original.is_empty() {
            Vec::new()
        } else {
            translations.gettext(None, original)?
        };
        let description = translated.as_slice();
        let mut position = 0;
        while description.len() - position > 78 - length {
            let end = position + 78 - length;
            let space = (position + 1..=end)
                .rev()
                .find(|&index| crate::native::whitespace(description[index]));
            if let Some(space) = space {
                out.extend_from_slice(&description[position..space]);
                out.push(b'\n');
                out.extend_from_slice(&[b' '; 31]);
                position = space + 1;
                length = 31;
            } else {
                out.extend_from_slice(&description[position..end]);
                out.push(b'\n');
                out.extend_from_slice(&[b' '; 31]);
                length = 31;
                position += 78 - length;
            }
        }
        if position < description.len() {
            out.extend_from_slice(&description[position..]);
            out.push(b'\n');
        }
        if description.is_empty() {
            out.push(b'\n');
        }
    }
    out.extend_from_slice(b"\nReport bugs to ");
    out.extend_from_slice(prefix(&project.bug_email));
    out.extend_from_slice(b".\nHome page: ");
    out.extend_from_slice(prefix(&project.homepage));
    out.push(b'\n');
    if project.is_gnu {
        out.extend_from_slice(b"General help using GNU software: http://www.gnu.org/gethelp/\n");
    }
    Ok(())
}
fn number_error(out: &mut Output, name: &[u8]) {
    out.error(
        b"You must pass a number to the `%s' option.\n",
        &[Value::Bytes(name)],
    );
}
fn decimal(input: &[u8], bits: u32) -> Option<(u64, bool)> {
    let mut position = 0;
    while input
        .get(position)
        .is_some_and(|&v| crate::native::whitespace(v))
    {
        position += 1;
    }
    let negative = input.get(position) == Some(&b'-');
    if negative || input.get(position) == Some(&b'+') {
        position += 1;
    }
    let start = position;
    let mut value = 0u64;
    while let Some(digit @ b'0'..=b'9') = input.get(position) {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
        position += 1;
    }
    if position == start || bits == 32 && value > u64::from(u32::MAX) {
        return None;
    }
    let number = if negative {
        if bits == 32 {
            u64::from((value as u32).wrapping_neg())
        } else {
            value.wrapping_neg()
        }
    } else {
        value
    };
    let tail = input[position..]
        .iter()
        .all(|&v| crate::native::whitespace(v));
    Some((number, tail))
}
/// uint helper retains a successful first assignment even when trailing junk
/// subsequently makes scanf return2. Mathematical overflow is safely rejected.
pub fn uint<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u32>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(value) = value else {
                return -1;
            };
            if value.first() == Some(&b'-') {
                out.error(
                    b"Your input for the '%s' option has to be a non negative number\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            }
            let Some((number, complete)) = decimal(value, 32) else {
                number_error(out, name);
                return -1;
            };
            if target.update(|v| *v = number as u32).is_err() {
                return -1;
            }
            if !complete {
                number_error(out, name);
                return -1;
            }
            1
        },
    )
}
/// uint16 helper assigns only after parse and explicit UINT16_MAX checks.
pub fn uint16<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u16>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some((number, true)) = value.and_then(|value| decimal(value, 32)) else {
                number_error(out, name);
                return -1;
            };
            if number > u64::from(u16::MAX) {
                out.error(
                    b"You must pass a number below 65535 to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            }
            if target.update(|v| *v = number as u16).is_err() {
                -1
            } else {
                1
            }
        },
    )
}
/// unsigned long long helper, including source negative modulo and partial assignment.
pub fn ulong<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u64>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some((number, complete)) = value.and_then(|value| decimal(value, 64)) else {
                number_error(out, name);
                return -1;
            };
            if target.update(|v| *v = number).is_err() {
                return -1;
            }
            if !complete {
                number_error(out, name);
                return -1;
            }
            1
        },
    )
}
/// Relative time helper uses the shared pinned fancy-time converter.
pub fn relative_time<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u64>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(number) = value.and_then(|v| gnunet_config::parse_relative_time(v).ok())
            else {
                out.error(
                    b"You must pass relative time to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            };
            if target.update(|v| *v = number).is_err() {
                -1
            } else {
                1
            }
        },
    )
}
/// Original fancy absolute parser: numeric epochs only above9999, native strptime
/// patterns share one zeroed tm, then native mktime and saturated microseconds.
pub fn parse_absolute(value: &[u8]) -> Result<u64, Error> {
    if value.eq_ignore_ascii_case(b"end of time") {
        return Ok(u64::MAX);
    }
    if let Some((number, true)) = decimal(value, 64)
        && number > 9999
        && !value.last().is_some_and(|&v| crate::native::whitespace(v))
    {
        return Ok(number.saturating_mul(1_000_000));
    }
    crate::native::absolute_calendar(value).map_err(|_| Error::InvalidInput)
}
/// Absolute time helper, assigning only on complete conversion.
pub fn absolute_time<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u64>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(number) = value.and_then(|v| parse_absolute(v).ok()) else {
                out.error(
                    b"You must pass absolute time to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            };
            if target.update(|v| *v = number).is_err() {
                -1
            } else {
                1
            }
        },
    )
}
/// Timestamp helper rejects non-second precision, including the source FOREVER
/// value whose UINT64_MAX is not divisible by a million.
pub fn timestamp<'a>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<u64>,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(number) = value.and_then(|v| parse_absolute(v).ok()) else {
                out.error(
                    b"You must pass a timestamp to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            };
            if !number.is_multiple_of(1_000_000) {
                out.error(
                    b"The maximum precision allowed for timestamps is seconds.\n",
                    &[],
                );
                return -1;
            }
            if target.update(|v| *v = number).is_err() {
                -1
            } else {
                1
            }
        },
    )
}

fn prefix(value: &[u8]) -> &[u8] {
    &value[..value.iter().position(|&v| v == 0).unwrap_or(value.len())]
}
/// Fixed-size base32 helper preserves source partial writes before malformed
/// data is detected. Generic storage permits an explicitly zeroizing destination.
pub fn base32_fixed<'a, T>(
    short: u8,
    name: &'a [u8],
    argument_help: &'a [u8],
    description: &'a [u8],
    target: Target<T>,
) -> Definition<'a>
where
    T: AsMut<[u8]> + 'a,
{
    Definition::new(
        spec(
            short,
            name,
            Some(argument_help),
            description,
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(value) = value else {
                return -1;
            };
            let mut cfg = gnunet_config::Configuration::new(gnunet_config::Limits::default());
            let installed = cfg.set_value(b"helper", b"value", Some(value));
            let decoded = if installed.is_ok() {
                target.update(|v| cfg.get_data(b"helper", b"value", v.as_mut()))
            } else {
                return -1;
            };
            if matches!(decoded, Ok(Ok(()))) {
                1
            } else {
                out.error(
                    b"Argument `%s' malformed. Expected base32 (Crockford) encoded value.\n",
                    &[Value::Bytes(name)],
                );
                -1
            }
        },
    )
}
/// Signed time-travel helper updates the supplied shared process-clock owner,
/// without altering the OS clock or the persistent speedup accumulation.
pub trait TimeTravelClock {
    /// Replace the logical GNUnet offset and publish any scheduler wake revision.
    fn replace_offset(&self, value: i64) -> Result<(), Error>;
}
impl TimeTravelClock for Rc<RefCell<crate::clock::Clock>> {
    fn replace_offset(&self, value: i64) -> Result<(), Error> {
        self.try_borrow_mut()
            .map_err(|_| Error::Conflict)?
            .set_offset(value);
        Ok(())
    }
}
impl TimeTravelClock for crate::shared_clock::SharedClock {
    fn replace_offset(&self, value: i64) -> Result<(), Error> {
        self.set_offset(value)
    }
}
/// Source time-travel option operating on the same explicit logical clock as
/// PROGRAM and Resolver; it never changes the host's system clock.
pub fn time_travel<'a>(
    short: u8,
    name: &'a [u8],
    clock: impl TimeTravelClock + 'a,
) -> Definition<'a> {
    Definition::new(
        spec(
            short,
            name,
            Some(b"[+/-]MICROSECONDS"),
            b"modify system time by given offset (for debugging/testing only)",
            Argument::Required,
        ),
        move |_: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
            let Some(mut value) = value else {
                return -1;
            };
            while value.first().is_some_and(|&v| crate::native::whitespace(v)) {
                value = &value[1..];
            }
            let negative = value.first() == Some(&b'-');
            if negative || value.first() == Some(&b'+') {
                value = &value[1..];
            }
            let Ok(relative) = gnunet_config::parse_relative_time(value) else {
                out.error(
                    b"You must pass a relative time (optionally with sign) to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            };
            if relative > i64::MAX as u64 {
                out.error(
                    b"Value given for time travel `%s' option is too big.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            }
            let delta = relative as i64;
            if clock
                .replace_offset(if negative { -delta } else { delta })
                .is_ok()
            {
                1
            } else {
                -1
            }
        },
    )
}
