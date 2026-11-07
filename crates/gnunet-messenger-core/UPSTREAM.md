# Official basis and intentional Rust structure

Pin: GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
`reference-inputs.json` identifies the selected public C/H inputs.

| Contract | Pinned active source |
| --- | --- |
| Room flags and epoch identifier bitfields | `src/include/gnunet_messenger_service.h:82`, `:147` |
| Actual member-ID reset/transition branches | `messenger_api.c:292-340` |
| Native-order reset producer/consumer | `gnunet-service-messenger_handle.c:801`; `messenger_api.c:308` |
| Official close: LEAVE whole-write then CLOSE | `messenger_api.c:821-833`, `:1416-1430` |
| Service sender/context hashes and original flags | `gnunet-service-messenger_handle.c:631-760` |
| Frontier, requested/discourse and merge handling | `gnunet-service-messenger_message_state.c` |
| Session creation, successor history and completion | `gnunet-service-messenger_member_session.c:34-90`, `:113-230`, `:260-363`, `:556-625` |
| Actual JOIN/LEAVE/KEY/ID/name/subscription handlers | `gnunet-service-messenger_message_handle.c:47-210`; `messenger_api_room.c:1287-1507` |
| Anonymous contact context | `messenger_api_contact.c:205-218`; `messenger_api_contact_store.c:64-98` |
| Owned deletion and history retrieval through deleted links | `gnunet-service-messenger_room.c:981-1134`; `messenger_api_room.c:449-520` |
| Inclusive subscription/time bounds and pruning | `gnunet-service-messenger_subscription.c`; `gnunet-service-messenger_room.c:1525-1547` |
| Actual capped delay helper | `messenger_api_message.c:1988-2021` |
| Actual snapshots JOIN/LEAVE/MERGE | `messenger_api_epoch.c:40-252`, `:369-423` |
| Exact successor KDF salts/info | `messenger_api_epoch_announcement.c:50-80`; `messenger_api_epoch_group.c:50-75` |
| Candidate selection ordering | `messenger_api_epoch.c:760-830`, `:884-951` |
| Group compatibility and membership subset | `messenger_api_epoch_group.c:507-563` |
| Original ACCESS/GROUP event and recipient linkage | `messenger_api_room.c:1835-1990`, `:2065-2093` |
| Non-group-only APPEAL | `messenger_api_room.c:1760-1834` |
| Announcement deletion only removes its confirmation | `messenger_api_room.c:481-508`; `messenger_api_epoch_announcement.c:478-495` |
| Revolution validity, retained historical key and following epochs | `messenger_api_epoch_announcement.c:522-560`; `messenger_api_epoch_group.c:375-430` |
|192-byte AUTH wire omits its required MAC16 | `messenger_api_message.c:439`, `:828`, `:1187`; extractor `:1945-1968`; handler `messenger_api_room.c:2094-2250` |

Rust deliberately stores one original frame with fixed metadata, generational
handles, inherited lineage and bounded iterative traversal rather than copying C
hash maps/linked lists/plugin or scheduler structures. Successful M3 checks and
private owned capabilities are consumed for decisions; no public token
constructor can create a successful cryptographic proof.

The C unique-confirmation replacement path increments its count again
(`messenger_api_epoch_membership.c:229-320`); Rust counts distinct contacts instead.
The C revolution handler reads `body.announcement.nonce` while processing a
REVOLUTION (`messenger_api_room.c:2000-2018`); Rust uses the typed revolution
nonce and admits it only after MAC verification. The C LEAVE allocation assumes
the removed contact exists (`messenger_api_epoch.c:125-155`); Rust explicitly
checks that membership before removal and cannot reproduce the absent-member
out-of-bounds write. Raw unsubscribe flag1 has its documented meaning and stops
renewal; Rust does not copy the service handler's ignored unsubscribe bit.

A self-signed JOIN introduces a member while its historical epoch references may
still be missing, avoiding circular authentication. Decryption and key/control
permissions remain separate from authentic outer DAG admission. In particular an
AUTHORIZATION key failure never becomes a fake Verified state and also cannot
poison the preceding authenticated vertex for every following official message.

The full-epoch driver changes internal scheduling, not the protocol: it uses the
existing non-group ANNOUNCEMENT/APPEAL/ACCESS handlers for key distribution and
can ratchet only a compatible previous verified cohort. It is not a byte-for-byte
copy of C timer/hash-map iteration order. Incoming group proposals remain real;
the omitted received AUTH MAC remains an explicit protocol limitation. No extra
field, private message, incompatible key derivation or purported old-bug
compatibility mode is added.
