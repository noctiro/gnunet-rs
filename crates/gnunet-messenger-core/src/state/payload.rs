//! Message bytes whose lifetime is independent of the room's graph metadata.

use crate::{Error, OwnedBytes, ShortLayout, wire};
use wire::{body::Body, message::Short, padding::Decode};

/// Authenticated plaintext and the exact producer layout used to decode it.
/// An installed plaintext can never lack its layout or padding policy.
pub(crate) struct Plaintext {
    bytes: OwnedBytes,
    pub layout: ShortLayout,
    padding: Decode,
}

impl Plaintext {
    pub fn new(bytes: OwnedBytes, layout: ShortLayout, padding: Decode) -> Self {
        Self {
            bytes,
            layout,
            padding,
        }
    }

    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub fn body(&self) -> Result<Body<'_>, Error> {
        Ok(Short::decode_with_profiles(
            self.bytes.expose(),
            self.layout.body,
            self.layout.padding,
            self.padding,
        )?
        .body())
    }
}
