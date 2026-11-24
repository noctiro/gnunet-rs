//! Official IDENTITY command options and the configured endpoint.

mod protected;
mod service;

use super::{Display, KeyType, Limits, Result, SecretKey, keys, messages, validate_name};
use gnunet::gnsrecord::ZoneKey;
use gnunet_config::{Configuration, ProjectData};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation},
    shared_clock::SharedClock,
};
use protected::Protected;
use std::{
    io::{self, Write},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(30);

struct Arguments {
    create: Target<Option<Vec<u8>>>,
    delete: Target<Option<Vec<u8>>>,
    ego: Target<Option<Vec<u8>>>,
    recipient: Target<Option<Vec<u8>>>,
    ecdsa: Target<i32>,
    display: Target<i32>,
    monitor: Target<i32>,
    quiet: Target<i32>,
    private: Target<i32>,
    verbose: Target<u32>,
}

struct Encryption {
    recipient: Vec<u8>,
    plaintext: Zeroizing<Vec<u8>>,
}

impl Encryption {
    fn write(self, out: &mut impl Write) -> Result<()> {
        let recipient = ZoneKey::from_ztld(std::str::from_utf8(&self.recipient)?)?;
        messages::encrypt_message(&recipient, &self.plaintext, TIMEOUT, out)
    }
}

struct Create {
    name: Vec<u8>,
    key_type: KeyType,
    imported: Option<SecretKey>,
}

struct Service {
    create: Option<Create>,
    delete: Option<Vec<u8>>,
    filter: Option<Vec<u8>>,
    list: bool,
    monitor: bool,
    private: bool,
    display: Display,
    encrypted: Option<Zeroizing<Vec<u8>>>,
    limits: Limits,
}

impl Arguments {
    fn new() -> Self {
        Self {
            create: Target::new(None),
            delete: Target::new(None),
            ego: Target::new(None),
            recipient: Target::new(None),
            ecdsa: Target::new(0),
            display: Target::new(0),
            monitor: Target::new(0),
            quiet: Target::new(0),
            private: Target::new(0),
            verbose: Target::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'C',
            b"create",
            b"NAME",
            b"Create an ego",
            self.create.clone(),
        ));
        options.add(helpers::string(
            b'D',
            b"delete",
            b"NAME",
            b"Delete an ego",
            self.delete.clone(),
        ));
        options.add(helpers::string(
            b'e',
            b"ego",
            b"NAME",
            b"Select a named ego",
            self.ego.clone(),
        ));
        options.add(helpers::string(
            b'k',
            b"key",
            b"PUBLIC_KEY",
            b"Set the recipient for -W",
            self.recipient.clone(),
        ));
        options.add(helpers::string(
            b'P',
            b"privkey",
            b"PRIVATE_KEY",
            b"Import an existing private key with -C",
            Target::new(None),
        ));
        options.add(helpers::string(
            b'R',
            b"read",
            b"MESSAGE",
            b"Decrypt a message for the ego chosen with -e",
            Target::new(None),
        ));
        options.add(helpers::string(
            b'W',
            b"write",
            b"MESSAGE",
            b"Encrypt a message for the public key chosen with -k",
            Target::new(None),
        ));
        options.add(helpers::flag(
            b'Y',
            b"ecdsa",
            b"Generate an ECDSA key with -C",
            self.ecdsa.clone(),
        ));
        options.add(helpers::flag(
            b'd',
            b"display",
            b"List egos",
            self.display.clone(),
        ));
        options.add(helpers::flag(
            b'm',
            b"monitor",
            b"Watch ego changes",
            self.monitor.clone(),
        ));
        options.add(helpers::flag(
            b'q',
            b"quiet",
            b"Print keys without their names",
            self.quiet.clone(),
        ));
        options.add(helpers::flag(
            b'p',
            b"private-keys",
            b"Include private keys in key output",
            self.private.clone(),
        ));
        options.add(helpers::verbose(self.verbose.clone()));
        options
    }

    fn select(&self, protected: Protected) -> Result<(Option<Encryption>, Service)> {
        let create = self.create.get()?;
        let delete = self.delete.get()?;
        let filter = self.ego.get()?;
        let encrypted = protected.read.map(protected::Value::into_payload);
        if let Some(bytes) = &encrypted {
            if filter.is_none() {
                return Err("IDENTITY -R/--read requires -e/--ego".into());
            }
            messages::validate(bytes, true)?;
        }
        let encryption = if let Some(plaintext) = protected.write {
            Some(Encryption {
                recipient: self
                    .recipient
                    .get()?
                    .ok_or("IDENTITY -W/--write requires -k/--key")?,
                plaintext: plaintext.into_payload(),
            })
        } else {
            None
        };
        let monitor = self.monitor.get()? != 0;
        let limits = Limits {
            reconnect: monitor,
            initialization_timeout: TIMEOUT,
            ..Limits::default()
        };
        for name in create.iter().chain(&delete) {
            #[cfg(windows)]
            std::str::from_utf8(name)?;
            validate_name(name, limits)?;
        }
        let create = if let Some(name) = create {
            Some(Create {
                name,
                key_type: if self.ecdsa.get()? != 0 {
                    KeyType::Ecdsa
                } else {
                    KeyType::Eddsa
                },
                imported: protected
                    .private
                    .as_ref()
                    .map(|value| keys::decode(value.payload()))
                    .transpose()?,
            })
        } else {
            None
        };
        Ok((
            encryption,
            Service {
                create,
                delete,
                filter,
                list: self.display.get()? != 0,
                monitor,
                private: self.private.get()? != 0,
                display: Display::Text {
                    quiet: self.quiet.get()? != 0,
                    verbose: self.verbose.get()? != 0,
                },
                encrypted,
                limits,
            },
        ))
    }
}

pub(crate) fn run() -> Result<()> {
    let mut environment = program::Environment::capture();
    let additions = environment.arguments.take().map(Zeroizing::new);
    let mut argv = gnunet_program_host::getopt::append_environment(
        std::env::args_os(),
        additions.as_ref().map(|value| value.as_slice()),
    )?;
    drop(additions);
    let arguments = Arguments::new();
    let options = arguments.options();
    let protected = Protected::take(&mut argv, environment.posixly_correct, options.specs())?;
    let clock = SharedClock::native(64)?;
    let config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    let mut logger = Logger::new(b"gnunet-identity", std::process::id(), false)?;
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: b"gnunet-identity",
            help: Some(b"Maintain GNUnet egos, display keys, or encrypt a message."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        options,
        argv,
        &environment,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(prepared) => prepared,
        Preparation::Stopped(stopped)
            if stopped.code == 0 && matches!(stopped.reason, program::StoppedReason::Options) =>
        {
            return Ok(());
        }
        Preparation::Stopped(stopped) => {
            return Err(format!(
                "PROGRAM stopped: {:?}, code {}",
                stopped.reason, stopped.code
            )
            .into());
        }
    };
    let main = prepared.main();
    if !main.arguments.is_empty() {
        return Err("unexpected positional IDENTITY arguments".into());
    }
    let (encryption, service) = arguments.select(protected)?;
    let mut out = io::stdout().lock();
    let encryption = encryption.map_or(Ok(()), |encryption| encryption.write(&mut out));
    if !service.required() {
        return encryption;
    }
    let mut diagnostics = io::stderr().lock();
    if let Err(error) = &encryption {
        writeln!(diagnostics, "{error}")?;
    }
    let out = &mut out;
    let diagnostics = &mut diagnostics;
    let result = crate::configured::run(main.config, clock, [b"identity"], move |[source]| {
        service.run(source, out, diagnostics)
    });
    result.and(encryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn standalone_identity_combines_mutations_inventory_and_envelopes() -> Result<()> {
        let arguments = Arguments::new();
        let options = arguments.options();
        let mut argv = [
            "gnunet-identity",
            "-C",
            "same",
            "-D",
            "same",
            "-e",
            "same",
            "-dm",
            "-k",
            "recipient",
            "-R",
            "cipher",
            "-W",
            "text",
        ]
        .map(OsString::from);
        let protected = Protected::take(&mut argv, false, options.specs())?;
        let parsed = options.run(b"gnunet-identity", argv, false);
        if !matches!(parsed.remaining(), Some([])) {
            return Err("unexpected positional IDENTITY arguments".into());
        }
        let (encryption, service) = arguments.select(protected)?;
        let encryption = encryption.ok_or("expected IDENTITY encryption")?;
        let create = service.create.ok_or("expected IDENTITY create")?;
        if encryption.recipient != b"recipient"
            || encryption.plaintext.as_slice() != b"text"
            || service.encrypted.as_ref().map(|bytes| bytes.as_slice())
                != Some(b"cipher".as_slice())
        {
            return Err("mixed operations changed the encryption options".into());
        }
        if create.name != b"same"
            || service.delete.as_deref() != Some(b"same".as_slice())
            || service.filter.as_deref() != Some(b"same".as_slice())
            || !service.list
            || !service.monitor
            || !service.limits.reconnect
        {
            return Err("mixed operations changed the inventory or mutation options".into());
        }
        Ok(())
    }
}
