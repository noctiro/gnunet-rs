# Public source and dependency provenance

The source reference is official GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
`official-source-inputs.json` identifies the selected public C/H/Meson inputs.

`messenger_api.c`: CREATE/room IPC, send filter, send_message_to_room SECRET decision, dequeue/sign/send, LEAVE sent→CLOSE, private transcript construction, one global handle key changes across rooms. `messenger_api_message.c`: kind eligibility, private/transcript/secret producer logic, signature/hash and active AUTHORIZATION body layout. `messenger_api_handle.c`: independent caller HashCode64 record secret, private FOREVER epoch/HPKE record AEAD, native flags, short lower-base32 labels and zone monitor. `gnunet-service-messenger_handle.c`: one-handle public-key/session notification matching and per-room source boundaries. `gnunet_messenger_service.h`: active caller-facing lifecycle/message API; `messenger.h`: IPC shape.

The package consumes the sealed message, crypto and room-state APIs, native
`submit_bounded`, room-lease retirement, explicit EpochRecord work/provider
capabilities and the HPKE record-recovery entry point.