//! Allocation-free admission of one complete native Messenger IPC frame.

use super::{ClientSend, EntryTarget};
use crate::{Error, Hash, OriginalLayout, ShortHash, wire};
use core::fmt;
use gnunet_types::Error as Fault;
use wire::{
    PublicKey, Request, Room, SensitiveBytes, envelope::Envelope, message::Message, padding,
};

/// One structurally valid request on a native connection accepted by the service.
/// The connection owner still admits room operations, membership and signatures.
#[derive(Clone, Copy, Debug)]
pub enum LocalRequest<'frame> {
    /// An idempotent control message on the accepted connection.
    Create,
    /// A request to retire the original connection and its room leases.
    Destroy,
    /// Open or enter a room on this connection.
    AdmitRoom(LocalRoomAdmission<'frame>),
    /// A request that requires a room lease owned by this connection.
    Room(LocalRoomRequest<'frame>),
}

/// The two ways a local connection can acquire a room lease.
#[derive(Clone, Copy, Debug)]
pub enum LocalRoomAdmission<'frame> {
    /// Host a room on this service.
    Open {
        /// Original wire fields, including the room key.
        room: Room<'frame>,
        /// Optional initial public key, subject to the connection's identity policy.
        public_key: Option<PublicKey<'frame>>,
    },
    /// Enter through the original requested door.
    Entry(LocalEntry<'frame>),
}

impl<'frame> LocalRequest<'frame> {
    /// Decode one exact official frame without copying or opening a room.
    /// The service accepts the native connection before this call. A reconnect
    /// can begin with OPEN or ENTRY without a preceding CREATE.
    ///
    /// # Errors
    /// Returns the official wire decoder's error for invalid lengths, fields or
    /// unsupported message types. SEND's inner message is decoded after routing.
    pub fn decode(frame: &'frame [u8]) -> Result<Self, Fault> {
        let command = match Request::decode(frame)? {
            Request::Create => return Ok(Self::Create),
            Request::Destroy => return Ok(Self::Destroy),
            Request::Open { room, public_key } => {
                return Ok(Self::AdmitRoom(LocalRoomAdmission::Open {
                    room,
                    public_key,
                }));
            }
            Request::Entry { room, public_key } => {
                return Ok(Self::AdmitRoom(LocalRoomAdmission::Entry(LocalEntry {
                    room,
                    public_key,
                })));
            }
            Request::Close { room } => LocalRoomCommand::Close { room },
            Request::Sync { room } => LocalRoomCommand::Sync { room },
            Request::Get { key, hash } => LocalRoomCommand::Get { key, hash },
            Request::Send { key, message } => LocalRoomCommand::Send(LocalSend {
                key,
                encoded: message,
            }),
        };
        Ok(Self::Room(LocalRoomRequest(command)))
    }
}

/// One original ENTRY, before its room and native route have been admitted.
#[derive(Clone, Copy, Debug)]
pub struct LocalEntry<'frame> {
    room: Room<'frame>,
    public_key: Option<PublicKey<'frame>>,
}

impl<'frame> LocalEntry<'frame> {
    /// Original wire fields, including the requested door.
    #[must_use]
    pub const fn room(self) -> Room<'frame> {
        self.room
    }

    /// Optional initial public key on the original request.
    #[must_use]
    pub const fn public_key(self) -> Option<PublicKey<'frame>> {
        self.public_key
    }

    /// Classify this door against the currently observed local service identity.
    #[must_use]
    pub fn target(self, local_peer: ShortHash) -> EntryTarget {
        EntryTarget::resolve(*self.room.door, local_peer)
    }
}

/// A structurally valid request whose original room must belong to the connection.
#[derive(Clone, Copy, Debug)]
pub struct LocalRoomRequest<'frame>(LocalRoomCommand<'frame>);

/// Dispatchable content of a request paired with its native room lease.
#[derive(Clone, Copy)]
pub enum LocalRoomCommand<'frame> {
    /// Close one room lease.
    Close {
        /// Original CLOSE fields.
        room: Room<'frame>,
    },
    /// Synchronize an existing room lease.
    Sync {
        /// Original SYNC fields.
        room: Room<'frame>,
    },
    /// Fetch one message from an existing room lease.
    Get {
        /// Original room key.
        key: &'frame Hash,
        /// Original requested message hash.
        hash: &'frame Hash,
    },
    /// Submit one original message to an existing room lease.
    Send(LocalSend<'frame>),
}

impl fmt::Debug for LocalRoomCommand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Close { .. } => "LocalRoomCommand::Close",
            Self::Sync { .. } => "LocalRoomCommand::Sync",
            Self::Get { .. } => "LocalRoomCommand::Get",
            Self::Send(_) => "LocalRoomCommand::Send",
        })
    }
}

impl<'frame> LocalRoomRequest<'frame> {
    /// Original key used to find the exact room lease on this connection.
    #[must_use]
    pub const fn key(self) -> &'frame Hash {
        match self.0 {
            LocalRoomCommand::Close { room } | LocalRoomCommand::Sync { room } => room.key,
            LocalRoomCommand::Get { key, .. } => key,
            LocalRoomCommand::Send(send) => send.key(),
        }
    }

    /// Pair this frame with its native room lease before the adapter dispatches it.
    /// The resolver must look up the supplied key on the original connection
    /// generation. A lease match does not establish authorization for the command.
    ///
    /// # Errors
    /// Propagates the lease resolver's error without creating a scoped request.
    pub fn scope<Lease, Failure>(
        self,
        resolve: impl FnOnce(&Hash) -> Result<Lease, Failure>,
    ) -> Result<ScopedLocalRoomRequest<'frame, Lease>, Failure> {
        Ok(ScopedLocalRoomRequest {
            lease: resolve(self.key())?,
            command: self.0,
        })
    }
}

/// A command paired with the matching native lease of its original connection.
pub struct ScopedLocalRoomRequest<'frame, Lease> {
    lease: Lease,
    command: LocalRoomCommand<'frame>,
}

impl<'frame, Lease> ScopedLocalRoomRequest<'frame, Lease> {
    /// Unpack the original lease and request for native dispatch.
    pub fn into_parts(self) -> (Lease, LocalRoomCommand<'frame>) {
        (self.lease, self.command)
    }
}

impl<Lease> fmt::Debug for ScopedLocalRoomRequest<'_, Lease> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ScopedLocalRoomRequest")
            .field(&self.command)
            .finish()
    }
}

/// A local SEND containing the original borrowed encoded message.
#[derive(Clone, Copy)]
pub struct LocalSend<'frame> {
    key: &'frame Hash,
    encoded: SensitiveBytes<'frame>,
}

impl fmt::Debug for LocalSend<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSend")
            .field("encoded", &self.encoded)
            .finish_non_exhaustive()
    }
}

impl<'frame> LocalSend<'frame> {
    /// Original room capability.
    #[must_use]
    pub const fn key(self) -> &'frame Hash {
        self.key
    }

    /// Original bytes for the adapter's producer layout and ownership policy.
    #[must_use]
    pub const fn encoded(self) -> SensitiveBytes<'frame> {
        self.encoded
    }

    /// Decode an unpadded candidate under the room source's declared layout.
    /// The caller still authenticates it against that exact client and room.
    ///
    /// # Errors
    /// Returns a framing, producer layout, or inadmissible message kind error.
    pub fn decode(self, layout: OriginalLayout) -> Result<ClientSend<'frame>, Error> {
        let bytes = self.encoded.expose();
        let kind = Envelope::decode(bytes)?.header()?.kind;
        let message = Message::decode_with_profiles(
            bytes,
            layout.body_profile(kind)?,
            layout.padding,
            padding::Decode::Absent,
        )?;
        Ok(ClientSend::new(message)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "Check original frame and scope")]
    fn entry_does_not_require_create_and_get_requires_a_resolved_lease() -> Result<(), Fault> {
        let key = [9; 64];
        let door = [3; 32];
        let mut frame = [0; wire::ROOM_LEN + 1];
        let n = Request::Entry {
            room: Room {
                door: &door,
                key: &key,
                previous: &[0; 64],
                epoch: &[0; 64],
            },
            public_key: None,
        }
        .encode(&mut frame)?;
        let LocalRequest::AdmitRoom(LocalRoomAdmission::Entry(entry)) =
            LocalRequest::decode(&frame[..n])?
        else {
            return Err(Fault::Malformed);
        };
        assert_eq!(entry.room().key, &key);
        assert_eq!(entry.target(door), EntryTarget::Local);
        assert!(matches!(
            entry.target([2; 32]),
            EntryTarget::Remote(remote) if remote.peer() == door
        ));
        assert!(matches!(
            LocalRequest::decode(&frame[..n + 1]),
            Err(Fault::InvalidInput)
        ));

        let hash = [6; 64];
        let n = Request::Get {
            key: &key,
            hash: &hash,
        }
        .encode(&mut frame)?;
        let LocalRequest::Room(request) = LocalRequest::decode(&frame[..n])? else {
            return Err(Fault::Malformed);
        };
        assert!(matches!(
            request.scope::<(), _>(|_| Err(Fault::NotFound)),
            Err(Fault::NotFound)
        ));
        let (lease, request) = request
            .scope(|original| {
                if original == &key {
                    Ok(7)
                } else {
                    Err(Fault::NotFound)
                }
            })?
            .into_parts();
        assert_eq!(lease, 7);
        assert!(
            matches!(request, LocalRoomCommand::Get { hash: original, .. } if original == &hash)
        );
        Ok(())
    }
}
