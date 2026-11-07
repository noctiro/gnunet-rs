# Public Rust boundaries

All core methods borrow caller buffers; no allocation, hidden randomness, IO, callbacks, or remote processing acknowledgement. Errors use the existing gnunet_types::Error.

| Rust boundary | Source meaning / authority |
| --- | --- |
| Aes256Gcm::from_bytes([u8;32]) | Exclusive opaque AES/H owner; local input copy erased; caller retained copies remain caller-owned |
| seal(nonce12,aad,&mut bytes) -> tag16 | Generic AES256-GCM primitive with explicit AAD; caller owns nonce uniqueness |
| open(nonce12,aad,&mut bytes,tag16) | Authenticity before decryption, failed range erased |
| validate_lengths(u64,u64) | Exact primitive preflight without enormous-buffer allocation |
| DatagramKey::derive(&Prk,u32) | get_iv_key/get_kid; serialBE32, source nonce12; no ACK/serial admission capability |
| kid()/nonce()/serial() | Public selectors and nonce; no key exporter |
| seal_body/open_body | Official source-empty AAD; caller supplies entire opaque body including padding/rekey/confirmation |
| seal_box/open_box | Explicit KID32/tag16 prefix, expected selector routing; no key-cache/replay/credit owner |
| seal_initial_payload/open_initial_payload | enc32/tag16 prefix and minimum opaque104-byte confirmation; no fake Elligator/identity validation |
| BoxView::parse/InitialView::parse | Borrowed byte prefix only; successful parse confers no authenticity |

Both new secret owners refuse Clone and Debug; positive compile controls may borrow their public fields and invoke seal/open. Shared `&self` encryption is deliberate primitive behavior, not a nonce allocator. The future communicator owner must allocate/retire serials before exposing any operation capability. No exporter bypass or hidden full-handshake success exists.

Resource errors precede mutation. An authentication error zeroes the would-be plaintext range and leaves unused caller tail alone; framing/serial/short-packet checks return existing InvalidInput/Truncated errors. Initial returned enc borrows input bytes and remains unauthenticated under a manually chosen master. C's try_decrypt may write plaintext before checktag fails; those C bytes are discarded, never compared as accepted output.
