use crate::{Proof, ipc};
use gnunet_types::Error;

/// SHA-512 input for the official REVOCATION SETU application and CADET port.
pub const APPLICATION_LABEL: &[u8] = b"revocation-set-union-application-id";
/// Official block type used as the SETU element type.
pub const ELEMENT_TYPE: u16 = gnunet_block::BlockType::REVOCATION.0 as u16;

/// Decode the exact full REVOKE frame held by one SETU element. This checks
/// framing and type only. It does not admit the certificate into the inventory.
pub fn decode(kind: u16, data: &[u8]) -> Result<Proof<'_>, Error> {
    if kind != ELEMENT_TYPE {
        return Err(Error::Unsupported);
    }
    match ipc::Request::decode(data)? {
        ipc::Request::Revoke(proof) => Ok(proof),
        ipc::Request::Query(_) => Err(Error::Malformed),
    }
}

/// Form the original complete SETU element payload, including the GNUnet
/// REVOKE message header and carried proof size.
pub fn encode(proof: Proof<'_>, output: &mut [u8]) -> Result<usize, Error> {
    ipc::Request::Revoke(proof).encode(output)
}
