//! Render only into bounded staging; enqueue is not a native write receipt.
use super::Writer;
use crate::Failure;
use gnunet_messenger_host::{self as api, wire::body::Body};
use std::io::{self, Write};
pub(crate) fn welcome(
    writer: &mut Writer,
    room: &api::Hash,
    talk: bool,
    silence: bool,
    enter: bool,
) -> io::Result<()> {
    if talk && !silence {
        return Ok(());
    }
    let mut encoded = [0; 103];
    let n = gnunet_gnsrecord::encode_base32(room, &mut encoded).map_err(io::Error::other)?;
    let mut out = writer.frame()?;
    out.write_all(if enter {
        b"* Entering room "
    } else {
        b"* Opening room "
    })?;
    out.write_all(&encoded[..n])?;
    out.write_all(b"\n")?;
    writer.enqueue(out, false)
}
pub(crate) fn joined(writer: &mut Writer, talk: bool, silence: bool) -> io::Result<()> {
    if talk && !silence {
        return Ok(());
    }
    let mut out = writer.frame()?;
    out.write_all(b"* You joined the room.\n")?;
    writer.enqueue(out, false)
}
pub(crate) fn message<'id>(
    api: &api::Api<'id, api::OsEntropy>,
    room: api::Room<'id>,
    message: api::MessageRef<'_, 'id>,
    talk: bool,
    silence: bool,
    writer: &mut Writer,
) -> Result<bool, Failure> {
    let body = message.body()?;
    if talk {
        if let Body::Talk { data, .. } = body
            && !silence
            && !message.local_sent()
        {
            let mut out = writer.frame()?;
            out.write_all(data.expose())?;
            writer.enqueue(out, true)?;
            return Ok(true);
        }
        return Ok(false);
    }
    if silence {
        return Ok(false);
    }
    let mut out = writer.frame()?;
    if let Some(sender) = message.sender() {
        if let Some(name) = api.state().contact_name(sender)? {
            out.write_all(name)?;
        } else {
            out.write_all(b"anonymous")?;
        }
    } else {
        out.write_all(b"peer")?;
    }
    out.write_all(if message.is_private() {
        b" [private]: "
    } else {
        b": "
    })?;
    out.write_all(if message.local_sent() { b"> " } else { b"< " })?;
    match body {
        Body::Info { version } => write!(out, "* protocol {version}")?,
        Body::Join { .. } => out.write_all(b"* joins the room")?,
        Body::Leave { .. } => out.write_all(b"* leaves the room")?,
        Body::Text { text } => out.write_all(text.content().expose())?,
        Body::Name { name } => {
            out.write_all(b"* name ")?;
            out.write_all(name.content().expose())?;
        }
        Body::Key { .. } => out.write_all(b"* updates member keys")?,
        Body::Peer { peer } => field(&mut out, b"* room open on ", peer)?,
        Body::Id { id } => field(&mut out, b"* member id ", id)?,
        Body::Miss { peer } => field(&mut out, b"* misses peer ", peer)?,
        Body::Merge { previous, .. } => field(&mut out, b"* merges ", previous)?,
        Body::Request { hash } => field(&mut out, b"* requests ", hash)?,
        Body::Invite { door, room_key } => {
            field(&mut out, b"* invitation via ", door)?;
            field(&mut out, b" to ", room_key)?;
        }
        Body::File { name, uri, .. } => {
            out.write_all(b"* shares ")?;
            out.write_all(name.expose())?;
            out.write_all(b"\n")?;
            out.write_all(uri.content().expose())?;
        }
        Body::Private { .. } => out.write_all(b"* private ciphertext")?,
        Body::Deletion { hash, .. } => field(&mut out, b"* deletes ", hash)?,
        Body::Connection { amount, flags } => {
            write!(out, "* connection details {amount}, {flags:x}")?;
        }
        Body::Ticket { identifier } => {
            out.write_all(b"* ticket ")?;
            out.write_all(identifier.content().expose())?;
        }
        Body::Transcript { hash, .. } => field(&mut out, b"* transcript of ", hash)?,
        Body::Tag { hash, tag } => {
            field(&mut out, b"* tag on ", hash)?;
            out.write_all(b": ")?;
            out.write_all(tag.content().expose())?;
        }
        Body::Subscription { discourse, .. } => field(&mut out, b"* subscribes ", discourse)?,
        Body::Talk { discourse, data } => {
            write!(out, "* talks {} bytes in ", data.len())?;
            field(&mut out, b"", discourse)?;
        }
        Body::Announcement { identifier, .. } => {
            field(&mut out, b"* announces epoch ", identifier)?
        }
        Body::Secret { identifier, .. } => field(&mut out, b"* epoch ciphertext for ", identifier)?,
        Body::Appeal { event, .. } => field(&mut out, b"* appeals epoch at ", event)?,
        Body::Access { event, .. } => field(&mut out, b"* grants epoch access at ", event)?,
        Body::Revolution { identifier, .. } => field(&mut out, b"* retires epoch ", identifier)?,
        Body::Group {
            identifier,
            initiator,
            partner,
            ..
        } => {
            field(&mut out, b"* proposes group ", identifier)?;
            field(&mut out, b" of ", initiator)?;
            field(&mut out, b", ", partner)?;
        }
        Body::Authorization {
            identifier, event, ..
        } => {
            field(&mut out, b"* authorizes group ", identifier)?;
            field(&mut out, b" at ", event)?;
        }
    }
    out.write_all(b"\n")?;
    writer.enqueue(out, true)?;
    let _original_room = room;
    Ok(true)
}

// Public identifiers only; never serialize encrypted key material, MACs or nonces.
fn field(out: &mut impl Write, label: &[u8], value: &[u8]) -> io::Result<()> {
    let mut encoded = [0; 103];
    let used = gnunet_gnsrecord::encode_base32(value, &mut encoded).map_err(io::Error::other)?;
    out.write_all(label)?;
    out.write_all(&encoded[..used])
}

// The selected Logger has already received the terminal diagnostic. The caller
// must not bypass -L/-l with a second unconditional stderr write.
