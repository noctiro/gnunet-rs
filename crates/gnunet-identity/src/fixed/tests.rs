use super::*;

type Fixed<'memory> = Owner<'memory, 3, 128>;

fn prepared<'owner, 'memory>(
    owner: &'owner mut Fixed<'memory>,
    mutation: Mutation<'_>,
    scratch: &mut NameScratch<128>,
) -> Result<Prepared<'owner, 'memory, 3, 128>, Error> {
    match owner.prepare(mutation, scratch)? {
        Decision::Prepared(original) => Ok(original),
        Decision::Immediate(_) => Err(Error::Conflict),
    }
}

#[test]
fn import_normalization_and_lookup_preserve_newest_first() -> Result<(), Error> {
    let mut inventory = Inventory::EMPTY;
    let mut scratch = NameScratch::EMPTY;
    let key = SecretKey::anonymous();
    inventory.restore(b"b.zone", key.view()?, &mut scratch)?;
    inventory.restore(b"zone", key.view()?, &mut scratch)?;
    let mut owner = Fixed::new(&mut inventory)?;
    let changes = prepared(
        &mut owner,
        Mutation::Create {
            name: "ÉGOΣ".as_bytes(),
            key: key.view()?,
        },
        &mut scratch,
    )?;
    const CANONICAL: &[u8] = "égoς".as_bytes();
    let change = changes.persist(|rows| {
        if rows.len() == 3 && rows.map(|row| row.name).eq([CANONICAL, b"b.zone", b"zone"]) {
            Ok(())
        } else {
            Err(CommitError::Failed(Error::Conflict))
        }
    })?;
    if !matches!(change.response()?, Response::Update { name: Some(name), .. } if name == CANONICAL)
    {
        return Err(Error::Conflict);
    }
    if !matches!(
        owner.prepare(
            Mutation::Create {
                name: CANONICAL,
                key: key.view()?
            },
            &mut scratch
        )?,
        Decision::Immediate(Code::NAME_CONFLICT)
    ) {
        return Err(Error::Conflict);
    }
    if owner.lookup(b"ZONE", false)?.map(|row| row.name) != Some(&b"zone"[..])
        || owner.lookup(b"prefix.b.zone", true)?.map(|row| row.name) != Some(&b"b.zone"[..])
        || owner.lookup("ÉGOΣ".as_bytes(), false)?.is_some()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn failed_and_uncertain_publication_never_expose_staged_identity() -> Result<(), Error> {
    let mut inventory = Inventory::EMPTY;
    let mut scratch = NameScratch::EMPTY;
    let key = SecretKey::anonymous();
    inventory.restore(b"first", key.view()?, &mut scratch)?;
    inventory.restore(b"last", key.view()?, &mut scratch)?;
    {
        let mut owner = Fixed::new(&mut inventory)?;
        let rename = Mutation::Rename {
            old: b"FIRST",
            new: b"changed",
        };
        if !matches!(
            prepared(&mut owner, rename, &mut scratch)?
                .persist(|_| Err(CommitError::Failed(Error::Storage))),
            Err(Error::Storage)
        ) || owner.lookup(b"changed", false)?.is_some()
        {
            return Err(Error::Conflict);
        }
        let change = prepared(&mut owner, rename, &mut scratch)?.persist(|rows| {
            if rows.map(|row| row.name).eq([&b"changed"[..], b"last"]) {
                Ok(())
            } else {
                Err(CommitError::Failed(Error::Conflict))
            }
        })?;
        if change.kind() != ChangeKind::Rename {
            return Err(Error::Conflict);
        }
        let delete = Mutation::Delete { name: b"last" };
        let change = prepared(&mut owner, delete, &mut scratch)?.persist(|rows| {
            if rows.map(|row| row.name).eq([&b"changed"[..]]) {
                Ok(())
            } else {
                Err(CommitError::Failed(Error::Conflict))
            }
        })?;
        if !matches!(change.response()?, Response::Update { name: None, key: deleted } if deleted.expose_serialized() == key.expose_serialized())
        {
            return Err(Error::Conflict);
        }
        drop(change);
        let delete = Mutation::Delete { name: b"changed" };
        if !matches!(
            prepared(&mut owner, delete, &mut scratch)?
                .persist(|_| Err(CommitError::OutcomeUnknown)),
            Err(Error::OutcomeUnknown)
        ) || !matches!(owner.egos(), Err(Error::OutcomeUnknown))
        {
            return Err(Error::Conflict);
        }
        owner.clear();
    }
    if !matches!(Fixed::new(&mut inventory), Err(Error::OutcomeUnknown)) {
        return Err(Error::Conflict);
    }
    inventory.clear();
    inventory.restore(b"loaded", key.view()?, &mut scratch)?;
    let owner = Fixed::new(&mut inventory)?;
    if owner.lookup(b"loaded", false)?.is_none() {
        return Err(Error::Conflict);
    }
    Ok(())
}
