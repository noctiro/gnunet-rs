//! Exact V2 frontier metadata, independent of native ownership.
use super::State;
use gnunet_crypto::EddsaPublicKey;
use std::io;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    pub(super) id: [u8; 32],
    pub(super) local: EddsaPublicKey,
    pub(super) minimum: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Persisted {
    pub(super) state: State,
    pub(super) binding: Binding,
}
impl Persisted {
    pub(super) fn bytes(self) -> [u8; 89] {
        gnunet_tcp_replay_host::pairing::FrontierImage {
            dirty: self.state.dirty,
            reserved: self.state.reserved,
            ledger: self.binding.id,
            local: self.binding.local,
            minimum: self.binding.minimum,
        }
        .encode()
    }
    pub(super) fn decode(bytes: [u8; 89]) -> io::Result<Self> {
        let value = gnunet_tcp_replay_host::pairing::FrontierImage::decode(bytes)?;
        Ok(Self {
            state: State {
                dirty: value.dirty,
                reserved: value.reserved,
            },
            binding: Binding {
                id: value.ledger,
                local: value.local,
                minimum: value.minimum,
            },
        })
    }
}
