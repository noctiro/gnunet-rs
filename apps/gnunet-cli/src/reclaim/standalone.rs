//! Official RECLAIM PROGRAM flags over configured service endpoints.
pub(super) mod output;
#[cfg(all(test, unix))]
mod tests;

use super::{
    Action, Command, Name, OutputMode, RelativeTime, Result, Ticket, Uri, credentials,
    execute_actions, identity,
};
use gnunet::clients::reclaim::Identifier;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{io, time::Duration};
use zeroize::Zeroizing;

type Text = Target<Option<Vec<u8>>>;

struct Plan {
    ego: Zeroizing<Vec<u8>>,
    commands: Vec<Command>,
}

struct Arguments {
    add: Text,
    delete: Text,
    value: Text,
    ego: Text,
    uri: Text,
    dump: Target<i32>,
    credentials: Target<i32>,
    credential_id: Text,
    credential_name: Text,
    issue: Text,
    consume: Text,
    revoke: Text,
    attribute_type: Text,
    credential_type: Text,
    tickets: Target<i32>,
}

impl Arguments {
    fn new() -> Self {
        Self {
            add: Target::new(None),
            delete: Target::new(None),
            value: Target::new(None),
            ego: Target::new(None),
            uri: Target::new(None),
            dump: Target::new(0),
            credentials: Target::new(0),
            credential_id: Target::new(None),
            credential_name: Target::new(None),
            issue: Target::new(None),
            consume: Target::new(None),
            revoke: Target::new(None),
            attribute_type: Target::new(None),
            credential_type: Target::new(None),
            tickets: Target::new(0),
        }
    }

    fn options(&self, expiration: Target<u64>) -> Options<'static> {
        let mut options = Options::new();
        let strings: [(_, &[u8], &[u8], &[u8], _); 12] = [
            (
                b'a',
                b"add",
                b"NAME",
                b"Add or update an attribute NAME",
                &self.add,
            ),
            (
                b'd',
                b"delete",
                b"ID",
                b"Delete the attribute with ID",
                &self.delete,
            ),
            (
                b'V',
                b"value",
                b"VALUE",
                b"The attribute VALUE",
                &self.value,
            ),
            (b'e', b"ego", b"EGO", b"The EGO to use", &self.ego),
            (
                b'U',
                b"rpuri",
                b"RPURI",
                b"Specify the relying party URI for a ticket",
                &self.uri,
            ),
            (
                b'I',
                b"credential-id",
                b"CREDENTIAL_ID",
                b"Credential to use for attribute",
                &self.credential_id,
            ),
            (
                b'N',
                b"credential-name",
                b"NAME",
                b"Credential name",
                &self.credential_name,
            ),
            (
                b'i',
                b"issue",
                b"A1,A2,...",
                b"Issue a ticket for a set of attributes separated by comma",
                &self.issue,
            ),
            (
                b'C',
                b"consume",
                b"TICKET",
                b"Consume a ticket",
                &self.consume,
            ),
            (b'R', b"revoke", b"TICKET", b"Revoke a ticket", &self.revoke),
            (
                b't',
                b"type",
                b"TYPE",
                b"Type of attribute",
                &self.attribute_type,
            ),
            (
                b'u',
                b"credential-type",
                b"TYPE",
                b"Type of credential",
                &self.credential_type,
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
        // Pinned C accepts this historical field but only forwards --rpuri.
        options.add(helpers::string(
            b'r',
            b"rp",
            b"RP",
            b"Specify the relying party for issue",
            Target::new(None),
        ));
        options.add(helpers::flag(
            b'D',
            b"dump",
            b"List attributes for EGO",
            self.dump.clone(),
        ));
        options.add(helpers::flag(
            b'A',
            b"credentials",
            b"List credentials for EGO",
            self.credentials.clone(),
        ));
        options.add(helpers::flag(
            b'T',
            b"tickets",
            b"List tickets of ego",
            self.tickets.clone(),
        ));
        options.add(helpers::relative_time(
            b'E',
            b"expiration",
            b"INTERVAL",
            b"Expiration interval of the attribute",
            expiration,
        ));
        options
    }

    fn plan(&self, expiration: u64) -> Result<Plan> {
        let ego = Zeroizing::new(self.ego.get()?.ok_or("Ego is required")?);
        if ego.is_empty() || ego.len() > identity::Limits::default().name_bytes || ego.contains(&0)
        {
            return Err("RECLAIM ego name is empty or exceeds its byte bound".into());
        }
        let mut commands = Vec::new();
        commands.try_reserve_exact(9)?;
        if let Some(name) = self.credential_name.get()? {
            let value = self.value.get()?.ok_or("Credential value missing!")?;
            commands.push(self.store(Action::CredentialStore, name, value)?);
        }
        if let Some(name) = self.add.get()? {
            let value = self.value.get()?.ok_or("Attribute value missing!")?;
            commands.push(self.store(Action::AttributeStore, name, value)?);
        }
        if let Some(id) = self.delete.get()? {
            let mut command = Command::new(Action::AttributeDelete);
            command.id = Some(identifier(&id)?);
            commands.push(command);
        }
        if let Some(ticket) = self.revoke.get()? {
            let mut command = Command::new(Action::TicketRevoke);
            command.ticket = revoke_name(ticket)?;
            commands.push(command);
        }
        // Ticket issuance resamples attributes after preceding mutations settle.
        if let Some(requested) = self.issue.get()? {
            commands.push(self.issue(&requested)?);
        }
        if let Some(ticket) = self.consume.get()? {
            let mut command = Command::new(Action::TicketConsume);
            command.ticket = ticket_name(ticket)?;
            command.uri = self.relying_party()?;
            command.timeout = Duration::from_secs(10);
            commands.push(command);
        }
        if self.credentials.get()? != 0 {
            commands.push(Command::new(Action::CredentialList));
        }
        if self.dump.get()? != 0 {
            commands.push(Command::new(Action::AttributeList));
        }
        if self.tickets.get()? != 0 {
            commands.push(Command::new(Action::TicketList));
        }
        for command in &mut commands {
            command.expiration = RelativeTime::from_micros(expiration);
            // Standalone listings require the service's natural END.
            command.limit = super::MAX_ROWS;
        }
        Ok(Plan { ego, commands })
    }

    fn issue(&self, requested: &[u8]) -> Result<Command> {
        let mut command = Command::new(Action::TicketIssue);
        command.uri = self.relying_party()?;
        if requested.len() > command.limits.frame_bytes {
            return Err("attribute selectors exceed one official frame".into());
        }
        for name in requested
            .split(|byte| *byte == b',')
            .filter(|name| !name.is_empty())
        {
            if command
                .names
                .iter()
                .any(|seen| seen.eq_ignore_ascii_case(name))
            {
                continue;
            }
            if command.names.len() == command.limits.list_items {
                return Err("too many selected attributes".into());
            }
            command.names.try_reserve(1)?;
            command.names.push(Zeroizing::new(name.to_vec()));
        }
        if command.names.is_empty() {
            return Err("Issue requires at least one selected attribute".into());
        }
        Ok(command)
    }

    fn relying_party(&self) -> Result<Zeroizing<Vec<u8>>> {
        let uri = Zeroizing::new(
            self.uri
                .get()?
                .ok_or("Supply a relying party URI with --rpuri")?,
        );
        if uri.is_empty() {
            return Err("Relying party URI is empty".into());
        }
        Uri::new(&uri)?;
        Ok(uri)
    }

    fn store(&self, action: Action, name: Vec<u8>, value: Vec<u8>) -> Result<Command> {
        let mut command = Command::new(action);
        let name = match std::str::from_utf8(&name) {
            Ok(text) => text.to_lowercase().into_bytes(),
            Err(_) => name.to_ascii_lowercase(),
        };
        command.name = Zeroizing::new(name);
        Name::new(&command.name)?;
        let value = Zeroizing::new(value);
        match action {
            Action::AttributeStore => {
                if let Some(kind) = self.attribute_type.get()? {
                    command.kind = credentials::attribute_type(&kind)
                        .ok_or("unsupported RECLAIM attribute type")?
                        .value();
                }
                command.credential = self
                    .credential_id
                    .get()?
                    .map(|id| identifier(&id))
                    .transpose()?;
                command.value = command.text_value(&value)?;
            }
            Action::CredentialStore => {
                if let Some(kind) = self.credential_type.get()? {
                    let kind = credentials::credential_type(&kind)
                        .ok_or("unsupported RECLAIM credential type")?;
                    if kind == super::CredentialType::PABC && !credentials::PABC_ACTIVE {
                        return Err("The PABC credential provider is unavailable".into());
                    }
                    command.kind = kind.value();
                }
                // The official CLI supplies the original credential text size without its NUL.
                command.value = value;
            }
            _ => return Err("expected a RECLAIM store operation".into()),
        }
        command.validate_store()?;
        Ok(command)
    }
}

fn identifier(text: &[u8]) -> Result<Identifier> {
    let mut bytes = [0; 32];
    if gnunet::gnsrecord::decode_base32(text, &mut bytes)? != bytes.len() {
        return Err("expected a 32-byte RECLAIM identifier in GNUnet base32".into());
    }
    Ok(Identifier::new(bytes))
}

fn ticket_name(ticket: Vec<u8>) -> Result<Zeroizing<Vec<u8>>> {
    let ticket = Zeroizing::new(ticket);
    if ticket.is_empty() {
        return Err("Ticket name is empty".into());
    }
    Ticket::new(&ticket)?;
    Ok(ticket)
}

fn revoke_name(argument: Vec<u8>) -> Result<Zeroizing<Vec<u8>>> {
    if argument.len() <= 127 {
        return ticket_name(argument);
    }
    let argument = Zeroizing::new(argument);
    let mut decoded = Zeroizing::new([0; 128]);
    if gnunet::gnsrecord::decode_base32(&argument, &mut *decoded)? != decoded.len() {
        return Err("expected a ticket GNS name or the official base32 ticket struct".into());
    }
    let end = decoded
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated ticket GNS name")?;
    ticket_name(decoded[..end].to_vec())
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let expiration = Target::new(3_600_000_000);
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-reclaim",
        b"re:claimID command line tool",
        arguments.options(expiration.clone()),
    )?
    else {
        return Ok(());
    };
    let plan = arguments.plan(expiration.get()?)?;
    if plan.commands.is_empty() {
        return Ok(());
    }
    crate::configured::run(
        prepared.main().config,
        clock,
        [b"reclaim", b"identity"],
        |[reclaim, identity]| async move {
            execute_actions(
                &plan.commands,
                &plan.ego,
                reclaim,
                Some(identity),
                OutputMode::Text,
                &mut io::stdout().lock(),
            )
            .await
        },
    )
}
