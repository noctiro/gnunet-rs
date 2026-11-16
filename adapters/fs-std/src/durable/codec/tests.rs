//! Local recovery retains unavailable barriers instead of inventing sync success.
use super::{Event, FileIdentity, ModelError, decode_event, encode_event};
use crate::DirectorySync;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fixed local-format witnesses assert complete identities and unchanged native barrier observations"
)]
fn committed_event_keeps_unavailable_directory_barrier_and_refuses_old_format()
-> Result<(), ModelError> {
    let identity = FileIdentity::unix(7, 9);
    let event = Event::FileCommitted {
        id: [6; 64],
        identity,
        directory_sync: DirectorySync::Unavailable,
    };
    let (kind, mut bytes) = encode_event(&event)?;
    assert_eq!(bytes.len(), 2 + 64 + 32 + 1);
    assert_eq!(&bytes[..2], &[0, 3]);
    assert_eq!(&bytes[66..98], identity.as_bytes());
    assert_eq!(bytes[98], 3);
    let Event::FileCommitted {
        id,
        identity: decoded,
        directory_sync,
    } = decode_event(kind, &bytes)?
    else {
        return Err(ModelError::Format);
    };
    assert_eq!(id, [6; 64]);
    assert_eq!(decoded, identity);
    assert_eq!(directory_sync, DirectorySync::Unavailable);
    bytes[1] = 2;
    assert!(decode_event(kind, &bytes).is_err());
    Ok(())
}
