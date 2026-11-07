//! Actual generic Rust parser observer; all descriptors/values are owned fixtures.
use gnunet_program_host::getopt::{Argument, Context, Options, Output, Spec};
use std::{
    cell::Cell,
    io::{self, Write},
    rc::Rc,
};
fn hex(value: Option<&[u8]>) -> String {
    let Some(bytes) = value else {
        return "-".to_owned();
    };
    let digits = b"0123456789abcdef";
    let mut text = String::new();
    for byte in bytes {
        text.push(char::from(digits[usize::from(byte >> 4)]));
        text.push(char::from(digits[usize::from(byte & 15)]));
    }
    text
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let profile = std::env::var("OWNED_GETOPT_PROFILE").unwrap_or_default();
    let mut rows = match profile.as_str() {
        "optional" => vec![
            (b'o', b"optional".as_slice(), Argument::Optional),
            (b'a', b"alpha", Argument::None),
        ],
        "longonly" => vec![
            (0, b"first".as_slice(), Argument::None),
            (0, b"second", Argument::Required),
            (b'a', b"alpha", Argument::None),
        ],
        "question" => vec![
            (b'?', b"question".as_slice(), Argument::None),
            (b'a', b"alpha", Argument::None),
        ],
        "require" => vec![
            (b'+', b"plus".as_slice(), Argument::None),
            (b'a', b"alpha", Argument::None),
            (b'b', b"beta", Argument::Required),
        ],
        "return" => vec![
            (b'-', b"minus".as_slice(), Argument::None),
            (1, b"position", Argument::None),
            (b'a', b"alpha", Argument::None),
        ],
        "W" => vec![
            (b'W', b"world".as_slice(), Argument::None),
            (b';', b"semicolon", Argument::None),
            (b'a', b"alpha", Argument::None),
            (b'b', b"beta", Argument::Required),
            (b'c', b"betamax", Argument::None),
        ],
        _ => vec![
            (b'a', b"alpha".as_slice(), Argument::None),
            (b'b', b"beta", Argument::Required),
            (b'x', b"exclusive", Argument::None),
            (b'm', b"must", Argument::None),
        ],
    };
    let cleaned = Rc::new(Cell::new(0));
    let mut table = Options::new();
    for (index, (short, name, argument)) in rows.drain(..).enumerate() {
        let spec = Spec {
            short,
            name,
            argument,
            argument_help: None,
            description: Some(b"test"),
            mandatory: profile == "mandatory" && short == b'm',
            exclusive: short == b'x',
        };
        table.push(
            spec,
            |ctx: Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
                let result = (|| -> io::Result<()> {
                    write!(
                        out.stdout,
                        "C {} {} {}",
                        hex(Some(name)),
                        hex(value),
                        ctx.current_argument
                    )?;
                    for arg in ctx.argv {
                        write!(out.stdout, " {}", hex(Some(arg)))?;
                    }
                    writeln!(out.stdout)
                })();
                if result.is_err() {
                    return -1;
                }
                if name == b"exclusive" {
                    0
                } else if value == Some(b"fail") {
                    -1
                } else {
                    1
                }
            },
        );
        if index < 2 {
            let cleaned = Rc::clone(&cleaned);
            table.cleaner(move || cleaned.set(cleaned.get() + 1))?;
        }
    }
    let result = table.run(
        b"owned summary",
        std::env::args_os(),
        std::env::var_os("POSIXLY_CORRECT").is_some(),
    );
    let mut stdout = io::stdout();
    stdout.write_all(&result.output.stdout)?;
    writeln!(stdout, "RET {} CLEAN {}", result.code, cleaned.get())?;
    write!(stdout, "ARGV")?;
    for arg in &result.argv {
        write!(stdout, " {}", hex(Some(arg)))?;
    }
    writeln!(stdout)?;
    io::stderr().write_all(&result.output.stderr)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            drop(writeln!(io::stderr(), "{error}"));
            std::process::ExitCode::from(1)
        }
    }
}
