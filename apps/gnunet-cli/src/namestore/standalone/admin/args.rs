//! Official record administration PROGRAM flags and typed operations.
use super::{
    Buffers, Command, Delegation, Display, Edit, INCLUDE_MAINTENANCE, OMIT_PRIVATE, Operation,
    Record, Selector,
};
use crate::namestore::{RecordFlags, RecordType, Result, ZoneKey, identity, orphans};
use gnunet::gnsrecord_text::typename_to_number;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use zeroize::Zeroizing;

type Value = Target<Option<Vec<u8>>>;

pub(in crate::namestore::standalone) struct Arguments {
    add: Target<i32>,
    delete: Target<i32>,
    display: Target<i32>,
    monitor: Target<i32>,
    recordline: Target<i32>,
    public: Target<i32>,
    omit_private: Target<i32>,
    include_maintenance: Target<i32>,
    list_orphans: Target<i32>,
    purge_orphans: Target<i32>,
    purge_zone: Target<i32>,
    nickname: Value,
    name: Value,
    reverse: Value,
    kind: Value,
    value: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn composite_actions_keep_record_selection_and_nickname_independent() -> Result<()> {
        let common = crate::namestore::standalone::Arguments::new();
        let parsed = common.options().run(
            b"gnunet-namestore",
            [
                "gnunet-namestore",
                "-a",
                "-d",
                "-D",
                "-m",
                "-i",
                "local",
                "-n",
                "@",
                "-t",
                "A",
                "-V",
                "127.0.0.1",
                "-e",
                "10m",
                "-s",
                "-p",
                "-z",
                "demo",
            ]
            .map(OsString::from),
            false,
        );
        assert!(parsed.remaining().is_some_and(<[_]>::is_empty));
        let plan = common.admin.command(&common, None)?;
        let [
            Operation::Edit {
                label: address_label,
                edit: Edit::Add(address),
            },
            Operation::Edit {
                label: delete_label,
                edit: Edit::Delete(selector),
            },
            Operation::Edit {
                label: nickname_label,
                edit: Edit::Add(nickname),
            },
            Operation::Display(display),
        ] = plan.operations.as_slice()
        else {
            return Err("wrong NAMESTORE mutation and observation order".into());
        };
        assert_eq!(address_label.as_slice(), b"@");
        assert_eq!(delete_label, address_label);
        assert_eq!(nickname_label, address_label);
        assert_eq!(address.kind, RecordType::A);
        assert_eq!(address.value.as_slice(), [127, 0, 0, 1]);
        assert_eq!(address.expiration, 600_000_000);
        assert_eq!(
            address.flags,
            RecordFlags::RELATIVE_EXPIRATION.union(RecordFlags::SHADOW)
        );
        assert_eq!(selector.kind, Some(RecordType::A));
        assert_eq!(selector.filter, 0);
        assert_eq!(nickname.kind, RecordType::NICK);
        assert_eq!(nickname.expiration, u64::MAX);
        assert_eq!(nickname.flags, RecordFlags::PRIVATE);
        assert_eq!(display.kind, Some(RecordType::A));
        assert_eq!(display.filter, OMIT_PRIVATE);
        let monitor = plan.monitor.ok_or("missing continuous operation")?;
        assert_eq!(monitor.label.as_deref(), Some(b"@".as_slice()));
        Ok(())
    }
}

impl Arguments {
    pub(in crate::namestore::standalone) fn new() -> Self {
        Self {
            add: Target::new(0),
            delete: Target::new(0),
            display: Target::new(0),
            monitor: Target::new(0),
            recordline: Target::new(0),
            public: Target::new(0),
            omit_private: Target::new(0),
            include_maintenance: Target::new(0),
            list_orphans: Target::new(0),
            purge_orphans: Target::new(0),
            purge_zone: Target::new(0),
            nickname: Target::new(None),
            name: Target::new(None),
            reverse: Target::new(None),
            kind: Target::new(None),
            value: Target::new(None),
        }
    }

    pub(in crate::namestore::standalone) fn options(&self, options: &mut Options<'static>) {
        let flags: [(_, &[u8], &[u8], _); 11] = [
            (b'a', b"add", b"add record", &self.add),
            (b'd', b"delete", b"delete record", &self.delete),
            (b'D', b"display", b"display records", &self.display),
            (
                b'm',
                b"monitor",
                b"monitor changes in the namestore",
                &self.monitor,
            ),
            (
                b'r',
                b"recordline",
                b"Output in recordline format",
                &self.recordline,
            ),
            (
                b'p',
                b"public",
                b"create or list public record",
                &self.public,
            ),
            (
                b'o',
                b"omit-private",
                b"omit private records",
                &self.omit_private,
            ),
            (
                b'T',
                b"include-maintenance",
                b"do not filter maintenance records",
                &self.include_maintenance,
            ),
            (
                b'O',
                b"list-orphans",
                b"display orphaned records with their private zone recovery keys",
                &self.list_orphans,
            ),
            (
                b'P',
                b"purge-orphans",
                b"purge namestore of all orphans",
                &self.purge_orphans,
            ),
            (
                b'X',
                b"purge-zone-records",
                b"delete all records in the specified zone",
                &self.purge_zone,
            ),
        ];
        for (short, long, description, target) in flags {
            options.add(helpers::flag(short, long, description, target.clone()));
        }
        let strings: [(_, &[u8], &[u8], &[u8], _); 5] = [
            (
                b'i',
                b"nick",
                b"NICKNAME",
                b"set the desired nick name for the zone",
                &self.nickname,
            ),
            (
                b'n',
                b"name",
                b"NAME",
                b"name of the record to add/delete/display",
                &self.name,
            ),
            (
                b'Z',
                b"zone-to-name",
                b"KEY",
                b"determine our name for the given KEY",
                &self.reverse,
            ),
            (
                b't',
                b"type",
                b"TYPE",
                b"type of the record to add/delete/display",
                &self.kind,
            ),
            (
                b'V',
                b"value",
                b"VALUE",
                b"value of the record to add/delete",
                &self.value,
            ),
        ];
        for (short, long, value, description, target) in strings {
            options.add(helpers::string(
                short,
                long,
                value,
                description,
                target.clone(),
            ));
        }
    }

    pub(in crate::namestore::standalone) fn command(
        &self,
        common: &super::super::Arguments,
        delegation: Option<Delegation>,
    ) -> Result<Command> {
        let owner = common.zone.get()?;
        if owner.as_ref().is_some_and(|ego| {
            ego.is_empty() || ego.len() > identity::Limits::default().name_bytes || ego.contains(&0)
        }) {
            return Err("invalid local IDENTITY ego name".into());
        }
        let mut filter = 0;
        if self.omit_private.get()? != 0 {
            filter |= OMIT_PRIVATE;
        }
        if self.include_maintenance.get()? != 0 {
            filter |= INCLUDE_MAINTENANCE;
        }
        let public = self.public.get()? != 0;
        let label = self.name.get()?;
        if label.as_ref().is_some_and(|name| {
            name.is_empty() || name.len() > 255 || name.contains(&0) || name.contains(&b'.')
        }) {
            return Err("invalid NAMESTORE record label".into());
        }
        let nickname = self.nickname.get()?.map(Zeroizing::new);
        let reverse = self.reverse.get()?;
        let add = self.add.get()? != 0;
        let delete = self.delete.get()? != 0;
        let list_orphans = self.list_orphans.get()? != 0;
        let display = self.display.get()? != 0 && !list_orphans;
        let monitor = self.monitor.get()? != 0;
        let purge_orphans = self.purge_orphans.get()? != 0;
        let purge_zone = self.purge_zone.get()? != 0;
        if [list_orphans, purge_orphans, purge_zone]
            .into_iter()
            .filter(|flag| *flag)
            .count()
            > 1
        {
            return Err("select one NAMESTORE maintenance scope".into());
        }
        let named_action =
            add || delete || nickname.is_some() || reverse.is_some() || display && label.is_some();
        if owner.is_none() && (named_action || purge_zone) {
            return Err(
                "this NAMESTORE operation requires a local zone selected with --zone".into(),
            );
        }
        if (list_orphans || purge_orphans)
            && owner.is_some()
            && !(named_action || display || monitor)
        {
            return Err("orphan operations use all zones".into());
        }
        let kind = self
            .kind
            .get()?
            .map(|name| {
                let name = std::str::from_utf8(&name)?;
                if name.eq_ignore_ascii_case("ANY") {
                    Ok::<_, Box<dyn std::error::Error>>(RecordType::ANY)
                } else {
                    typename_to_number(name)
                        .ok_or_else(|| format!("unsupported record type `{name}'").into())
                }
            })
            .transpose()?
            .filter(|kind| *kind != RecordType::ANY);
        if (purge_orphans || purge_zone)
            && (label.is_some()
                || kind.is_some()
                || add
                || delete
                || nickname.is_some()
                || delegation.is_some())
        {
            return Err(
                "purge operates on entire label sets independently of record edits and selectors"
                    .into(),
            );
        }
        let recordline = self.recordline.get()? != 0;
        let format = |filter| Display {
            label: label.clone(),
            kind,
            recordline,
            filter,
        };
        let display_filter = if public {
            filter | OMIT_PRIVATE
        } else {
            filter
        };
        let mut operations = Vec::new();
        let mut nickname_record = None;
        // All finite actions are validated before any one can mutate NAMESTORE.
        if nickname.is_some() || add {
            let mut codec = Buffers::new()?;
            if let Some(nickname) = nickname {
                if nickname.is_empty() {
                    return Err("zone nickname is empty".into());
                }
                nickname_record = Some(Record::from_text(
                    &mut codec,
                    RecordType::NICK,
                    u64::MAX,
                    RecordFlags::PRIVATE,
                    &nickname,
                )?);
            }
            if add {
                let name = label.clone().ok_or("--add requires --name")?;
                let kind = kind.ok_or("--add requires a concrete --type")?;
                if [
                    RecordType::SRV,
                    RecordType::TLSA,
                    RecordType::SMIMEA,
                    RecordType::new(61),
                ]
                .contains(&kind)
                {
                    return Err("use a BOX record for SRV, TLSA, SMIMEA or OPENPGPKEY".into());
                }
                let value = Zeroizing::new(self.value.get()?.ok_or("--add requires --value")?);
                let expiration = common
                    .expiration
                    .get()?
                    .ok_or("--add requires --expiration")?;
                let (expiration, flags) = super::super::parse_expiration(&expiration)?;
                let mut flags = common.creation_flags(flags)?;
                if !public {
                    flags = flags.union(RecordFlags::PRIVATE);
                }
                let record = Record::from_text(&mut codec, kind, expiration, flags, &value)?;
                operations.push(Operation::Edit {
                    label: name,
                    edit: Edit::Add(record),
                });
            }
        }
        if delete {
            let name = label.clone().ok_or("--delete requires --name")?;
            let selector = Selector {
                kind,
                value: self.value.get()?.map(Zeroizing::new),
                filter,
            };
            operations.push(Operation::Edit {
                label: name,
                edit: Edit::Delete(selector),
            });
        }
        if let Some(delegation) = delegation {
            operations.push(Operation::Import(delegation));
        }
        // Official LOOKUP hides an existing apex nickname. Apply the explicit
        // nickname after any ordinary apex edit in this invocation.
        if let Some(record) = nickname_record {
            operations.push(Operation::Edit {
                label: b"@".to_vec(),
                edit: Edit::Add(record),
            });
        }
        if purge_orphans || purge_zone {
            let action = if purge_zone {
                orphans::Action::PurgeZone
            } else {
                orphans::Action::PurgeOrphans
            };
            operations.push(Operation::Maintenance {
                action,
                display: format(filter),
            });
        }
        if list_orphans {
            operations.push(Operation::Maintenance {
                action: orphans::Action::List,
                display: format(display_filter),
            });
        }
        if display {
            operations.push(Operation::Display(format(display_filter)));
        }
        if let Some(spelling) = reverse {
            let target = ZoneKey::from_ztld(std::str::from_utf8(&spelling)?)?;
            operations.push(Operation::Reverse { target, spelling });
        }
        let monitor = monitor.then(|| format(display_filter));
        if operations.is_empty() && monitor.is_none() {
            return Err("select a NAMESTORE record, display or maintenance operation".into());
        }
        Ok(Command {
            owner,
            operations,
            monitor,
        })
    }
}
