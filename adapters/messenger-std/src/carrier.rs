//! Desktop allocation for the shared Messenger carrier.

use gnunet_messenger_core::wire::{self, padding, profile::Profile};
use gnunet_types::Error;
use zeroize::Zeroizing;

use gnunet_messenger_core::carrier::{MAX_FRAME_BYTES, Prepared};
pub(crate) use gnunet_messenger_core::carrier::{VERSION, decode, port};

pub(crate) fn encode(
    raw: &[u8],
    layout: gnunet_messenger_core::OriginalLayout,
    decode: padding::Decode,
    output_profile: Profile,
    entropy: &mut impl gnunet_crypto::Entropy,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kind = wire::envelope::Envelope::decode(raw)?.header()?.kind;
    let profile = layout.body_profile(kind).map_err(|_| Error::Unsupported)?;
    let message =
        wire::message::Message::decode_with_profiles(raw, profile, layout.padding, decode)?;
    let prepared = Prepared::new(message, output_profile, MAX_FRAME_BYTES)?;
    let len = prepared.encoded_len();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    bytes.resize(len, 0);
    prepared.encode_into(&mut bytes, entropy)?;
    Ok(bytes)
}
