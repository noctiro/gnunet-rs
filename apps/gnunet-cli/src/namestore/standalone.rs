//! Configured NAMESTORE entry point and delegation handler.

mod admin;

use super::{Action, Command, RecordFlags, Result, identity};
use crate::configured;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{io, num::NonZeroUsize, time::Duration};

const NAMESTORE: &[u8] = b"namestore";
const DEFAULT_EGO: &[u8] = b"URI_IMPORT_EGO";
const DEFAULT_STDIN_BATCH: u32 = 1000;

struct Arguments {
    uri: Target<Option<Vec<u8>>>,
    expiration: Target<Option<Vec<u8>>>,
    zone: Target<Option<Vec<u8>>>,
    shadow: Target<i32>,
    maintenance: Target<i32>,
    stdin: Target<i32>,
    batch_size: Target<u32>,
    admin: admin::Arguments,
}

impl Arguments {
    fn new() -> Self {
        Self {
            uri: Target::new(None),
            expiration: Target::new(None),
            zone: Target::new(None),
            shadow: Target::new(0),
            maintenance: Target::new(0),
            stdin: Target::new(0),
            batch_size: Target::new(DEFAULT_STDIN_BATCH),
            admin: admin::Arguments::new(),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'u',
            b"uri",
            b"URI",
            b"Import a GNS delegation URI",
            self.uri.clone(),
        ));
        options.add(helpers::string(
            b'e',
            b"expiration",
            b"TIME",
            b"Set expiration, for example 1a or never",
            self.expiration.clone(),
        ));
        options.add(helpers::string(
            b'z',
            b"zone",
            b"EGO",
            b"Select the local IDENTITY ego for import",
            self.zone.clone(),
        ));
        options.add(helpers::flag(
            b's',
            b"shadow",
            b"Store as a shadow record",
            self.shadow.clone(),
        ));
        options.add(helpers::flag(
            b'M',
            b"maintenance",
            b"Store as a maintenance record",
            self.maintenance.clone(),
        ));
        options.add(helpers::flag(
            b'S',
            b"from-stdin",
            b"read official record-line groups from stdin",
            self.stdin.clone(),
        ));
        options.add(helpers::uint(
            b'B',
            b"batch-size",
            b"NUMBER",
            b"maximum label sets to buffer per stdin batch",
            self.batch_size.clone(),
        ));
        self.admin.options(&mut options);
        options
    }

    fn command(&self, config: &Configuration) -> Result<Command> {
        let uri = self.uri.get()?.ok_or("URI import requires -u/--uri")?;
        let expiration = self
            .expiration
            .get()?
            .ok_or("URI import requires -e/--expiration")?;
        let zone = self.zone.get()?;
        let ego = zone
            .as_deref()
            .or_else(|| config.get(NAMESTORE, DEFAULT_EGO))
            .ok_or("select a local IDENTITY ego with -z/--zone or [namestore] URI_IMPORT_EGO")?;
        if ego.is_empty() || ego.len() > identity::Limits::default().name_bytes || ego.contains(&0)
        {
            return Err("invalid local IDENTITY ego name".into());
        }
        let (expiration, flags) = parse_expiration(&expiration)?;
        let flags = self.creation_flags(flags)?;
        let mut command = Command::new(Action::ImportUri, ego.to_vec(), Duration::from_secs(30));
        command.set_delegation(std::str::from_utf8(&uri)?, expiration, flags)?;
        Ok(command)
    }

    fn creation_flags(&self, mut flags: RecordFlags) -> Result<RecordFlags> {
        if self.shadow.get()? != 0 {
            flags = flags.union(RecordFlags::SHADOW);
        }
        if self.maintenance.get()? != 0 {
            flags = flags.union(RecordFlags::MAINTENANCE);
        }
        Ok(flags)
    }
}

fn parse_expiration(value: &[u8]) -> Result<(u64, RecordFlags)> {
    if value == b"never" {
        return Ok((u64::MAX, RecordFlags::NONE));
    }
    if let Ok(expiration) = gnunet_config::parse_relative_time(value) {
        return Ok((expiration, RecordFlags::RELATIVE_EXPIRATION));
    }
    Ok((helpers::parse_absolute(value)?, RecordFlags::NONE))
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let Some((prepared, clock)) = configured::prepare(
        b"gnunet-namestore",
        b"GNUnet zone manipulation tool. Select a local IDENTITY ego with -z EGO. URI import can also use [namestore] URI_IMPORT_EGO.",
        arguments.options(),
    )? else { return Ok(()); };
    let config = prepared.main().config;
    if !prepared.main().arguments.is_empty() {
        return Err("unexpected positional arguments; select an operation with its options".into());
    }
    if arguments.stdin.get()? != 0 {
        let batch_size = NonZeroUsize::new(usize::try_from(arguments.batch_size.get()?)?)
            .ok_or("--batch-size must be positive")?;
        return configured::run(config, clock, [NAMESTORE, b"identity"], move |endpoints| {
            super::recordline::import_configured(endpoints, batch_size)
        });
    }
    let delegation = if arguments.uri.with(Option::is_some)? {
        let command = arguments.command(config)?;
        Some(admin::Delegation {
            owner: command.ego,
            sets: command
                .sets
                .ok_or("missing preflighted delegation record")?,
        })
    } else {
        None
    };
    let command = arguments.admin.command(&arguments, delegation)?;
    configured::run(
        config,
        clock,
        [NAMESTORE, b"identity"],
        move |[store, identity]| async move {
            admin::execute(command, store, identity, &mut io::stdout().lock()).await
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet::gnsrecord::{ZoneKey, ZoneKeyType};
    use gnunet_config::ProjectData;
    use std::{ffi::OsString, sync::Arc};

    #[test]
    fn default_dispatch_args_use_the_configured_ego_and_shared_store() -> Result<()> {
        let mut public_key = [0; 58];
        ZoneKey::new(ZoneKeyType::Edkey, [0x64; 32]).write_ztld(&mut public_key)?;
        let uri = format!("gnunet://gns/{}/shared", std::str::from_utf8(&public_key)?);
        let arguments = Arguments::new();
        let parsed = arguments.options().run(
            b"gnunet-namestore",
            ["gnunet-namestore", "-e", "1a", "-u", &uri].map(OsString::from),
            false,
        );
        assert!(parsed.remaining().is_some_and(<[_]>::is_empty));
        let mut config =
            Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
        assert!(arguments.command(&config).is_err());
        config.set_value(NAMESTORE, DEFAULT_EGO, Some(b"local-zone"))?;
        let configured = arguments.command(&config)?;
        let (direct, _) = super::super::parse(
            &[
                "import-uri",
                "namestore.sock",
                &uri,
                "--identity-socket",
                "identity.sock",
                "--ego",
                "local-zone",
                "--expiration-us",
                "31536000000000",
                "--relative",
                "1",
            ]
            .map(OsString::from),
        )?;
        assert_eq!(configured.ego, direct.ego);
        assert_eq!(configured.label.as_slice(), b"shared");
        let configured_sets = configured.sets.ok_or("missing configured store")?;
        let direct_sets = direct.sets.ok_or("missing direct store")?;
        assert_eq!(configured_sets.count, 1);
        assert_eq!(
            configured_sets.bytes.as_slice(),
            direct_sets.bytes.as_slice()
        );
        Ok(())
    }
}
