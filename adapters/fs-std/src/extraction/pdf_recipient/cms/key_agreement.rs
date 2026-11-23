//! Recipient selection shared by CMS key-agreement mechanisms.

use super::{Ber, CONTEXT_0, CONTEXT_1, INTEGER, Item, OCTETS, RecipientId, SEQUENCE};

const GENERALIZED_TIME: u8 = 0x18;

pub(super) struct Fields<'a> {
    pub(super) originator: Item<'a>,
    pub(super) ukm: Option<Item<'a>>,
    pub(super) algorithm: Item<'a>,
    pub(super) encrypted: Item<'a>,
}

pub(super) fn select<'a>(
    rid: &RecipientId,
    entry: Item<'a>,
    budget: &mut usize,
) -> Option<Option<Fields<'a>>> {
    let mut info = Ber(entry.data);
    if info.take(INTEGER)?.uint()? != 3 {
        return None;
    }
    let originator = info.take(CONTEXT_0)?;
    let ukm = info.optional(CONTEXT_1)?;
    let algorithm = info.take(SEQUENCE)?;
    let mut recipients = Ber(info.take(SEQUENCE)?.data);
    info.finish()?;
    if recipients.0.is_empty() {
        return None;
    }

    let mut selected = None;
    while !recipients.0.is_empty() {
        *budget = budget.checked_sub(1)?;
        let mut recipient = Ber(recipients.take(SEQUENCE)?.data);
        let identity = recipient.read()?;
        let encrypted = recipient.read()?;
        recipient.finish()?;
        let matches = match identity.tag {
            SEQUENCE => rid.issuer_and_serial(identity)?,
            CONTEXT_0 => {
                let mut rki = Ber(identity.data);
                let matches = rid.key_identifier(rki.read()?, OCTETS)?;
                rki.optional(GENERALIZED_TIME)?;
                rki.optional(SEQUENCE)?;
                rki.finish()?;
                matches
            }
            _ => return None,
        };
        if matches && selected.replace(encrypted).is_some() {
            return None;
        }
    }

    Some(selected.map(|encrypted| Fields {
        originator,
        ukm,
        algorithm,
        encrypted,
    }))
}

pub(super) fn explicit(field: Item<'_>) -> Option<Item<'_>> {
    let mut wrapper = Ber(field.data);
    let item = wrapper.read()?;
    wrapper.finish()?;
    Some(item)
}
