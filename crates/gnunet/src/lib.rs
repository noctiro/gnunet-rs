//! Independent Rust implementation of official GNUnet.
//!
//! The v0.29.1 feature inventory is versioned under `spec/gnunet`. This API
//! exposes implemented official components; the full peer is not complete yet.
#![no_std]
#![forbid(unsafe_code)]

/// Optional allocation-free raw QUIC/HTTP3 application profiles and bounded stream state.
/// Actual QUIC, TLS, HTTP3/QPACK and communicator IO require a separate runtime.
#[cfg(feature = "transport-quic")]
pub use gnunet_transport_quic as transport_quic;

/// Optional actual Raw QUIC/HTTP3 communicator with owned backend drivers,
/// bounded external receive pools and standard local service IPC.
#[cfg(all(feature = "official-quic-communicator", unix))]
pub use gnunet_quic_communicator_host as quic_communicator_host;

/// Optional actual DV ingress, private grant and native queue/receipt bridge.
#[cfg(all(feature = "official-transport-dv-bridge", unix))]
pub use gnunet_transport_dv_bridge_host as transport_dv_bridge;

/// Optional actual bounded PILS/DV runtime with original durable and live owners.
#[cfg(all(feature = "official-transport-dv-runtime", unix))]
pub use gnunet_transport_dv_runtime_host as transport_dv_runtime;

/// Optional qualified durable public DV sender-watermark provider.
#[cfg(all(feature = "official-transport-dv-store", unix))]
pub use gnunet_transport_dv_store_host as transport_dv_store;

/// Optional independent TRANSPORT SERVICE and original native providers.
#[cfg(all(feature = "official-transport-server", unix))]
pub use gnunet_transport_service_host as transport_service;

/// Optional noalloc actual DV KEM/AEAD material and bounded caller-storage cache.
#[cfg(feature = "transport-dv-crypto")]
pub use gnunet_transport_dv_crypto as transport_dv_crypto;
/// Optional original PILS sign/decapsulation jobs for real DV material.
#[cfg(all(feature = "official-transport-dv-crypto", unix))]
pub use gnunet_transport_dv_crypto_host as transport_dv_crypto_host;

/// Optional allocation-free testing-only UNIX communicator packet/address codec.
#[cfg(feature = "unix-communicator")]
pub use gnunet_unix_communicator as unix_communicator;
/// Optional original UNIX datagram, PILS and TRANSPORT communicator runtime.
#[cfg(all(feature = "official-unix-communicator", unix))]
pub use gnunet_unix_communicator_host as unix_communicator_host;

/// Optional actual DNS monitor and answer redirector PROGRAM utilities.
#[cfg(all(feature = "official-dns-tools", unix))]
pub use gnunet_dns_tools_host as dns_tools;
/// Optional bounded official zone publication material and scheduling core.
#[cfg(feature = "zonemaster-alloc")]
pub use gnunet_zonemaster as zonemaster;
/// Optional native zone publication composition with a required caller DHT port.
#[cfg(all(feature = "official-zonemaster", unix))]
pub use gnunet_zonemaster_host as zonemaster_host;

/// Optional allocation-free official DNS helper envelope and explicit phase core.
#[cfg(feature = "dns-interception")]
pub use gnunet_dns_interception as dns_interception;
/// Optional native DNS interception SERVICE and original Rust helper ownership.
#[cfg(all(feature = "official-dns-server", unix))]
pub use gnunet_dns_service_host as dns_service;

/// Optional allocation-free official HOSTLIST advertisement and body framing.
#[cfg(feature = "hostlist")]
pub use gnunet_hostlist as hostlist;
/// Optional native HOSTLIST HTTP/TLS, CORE and PEERSTORE composition.
#[cfg(all(feature = "official-hostlist", unix))]
pub use gnunet_hostlist_host as hostlist_host;

/// Optional noalloc current TESTBED resource ownership.
#[cfg(feature = "testbed")]
pub use gnunet_testbed as testbed;
/// Optional TESTBED native configuration, owned paths and actual port probes.
#[cfg(all(feature = "official-testbed", unix))]
pub use gnunet_testbed_host as testbed_host;

/// Optional noalloc PT packet transformations and explicit bounded business core.
#[cfg(feature = "pt")]
pub use gnunet_pt as pt;
/// Optional PT native DNS/VPN/CADET composition with explicit DHT discovery port.
#[cfg(all(feature = "official-pt", unix))]
pub use gnunet_pt_host as pt_host;

/// Optional noalloc official NAT IPC, STUN and traversal packet contracts.
#[cfg(feature = "nat")]
pub use gnunet_nat as nat;
/// Optional actual interface, Resolver, STUN and IGD platform owners.
#[cfg(all(feature = "official-nat", unix))]
pub use gnunet_nat_host as nat_host;

/// Optional caller-driven public NAT burst socket owner.
#[cfg(all(feature = "official-nat-burst", unix))]
pub use gnunet_nat_burst_host as nat_burst_host;

/// Optional official revocation certificates, IPC and caller-scheduled work.
#[cfg(feature = "revocation")]
pub use gnunet_revocation as revocation;
/// Optional durable REVOCATION service with original CORE/SETU providers.
#[cfg(all(feature = "official-revocation-server", unix))]
pub use gnunet_revocation_host as revocation_host;
/// Optional noalloc topology contracts and explicit allocated HELLO gossip policy.
#[cfg(feature = "topology")]
pub use gnunet_topology as topology;
/// Optional caller-driven TOPOLOGY daemon with original native providers.
#[cfg(all(feature = "official-topology", unix))]
pub use gnunet_topology_host as topology_host;

/// Optional allocation-free official DID identifiers and document formats.
#[cfg(feature = "did")]
pub use gnunet_did as did;

/// Optional local DATACACHE API and explicit-alloc memory backend.
#[cfg(feature = "datacache")]
pub use gnunet_datacache as datacache;
#[cfg(feature = "gnsrecord-text")]
pub use gnunet_gnsrecord_text as gnsrecord_text;
#[cfg(feature = "json")]
pub use gnunet_json as json;
#[cfg(feature = "messenger")]
pub use gnunet_messenger as messenger;
/// Optional bounded MESSENGER room/member/message state with explicit native ports.
#[cfg(feature = "messenger-state")]
pub use gnunet_messenger_core as messenger_core;
/// Optional native MESSENGER SERVICE with shared CADET relay and PILS signer.
#[cfg(all(feature = "official-messenger-server", unix))]
pub use gnunet_messenger_service_host as messenger_service;
/// Optional NAMESTORE record policy and explicit-alloc authority/stream owners.
#[cfg(feature = "namestore")]
pub use gnunet_namestore as namestore;
/// Optional NAMESTORE service with original durable snapshot worker receipts.
#[cfg(all(feature = "official-namestore-server", unix))]
pub use gnunet_namestore_host as namestore_host;
/// Optional owned OIDC signing provider using AWS-LC native/assembly primitives.
#[cfg(all(feature = "official-rest-oidc", unix))]
pub use gnunet_oidc_crypto_host as oidc_crypto;
/// Optional allocation-free RECLAIM objects and active IPC codecs.
#[cfg(feature = "reclaim")]
pub use gnunet_reclaim as reclaim;
/// Optional bounded RECLAIM credential parsing, presentation and attribute helpers.
#[cfg(feature = "reclaim-credentials")]
pub use gnunet_reclaim_credentials as reclaim_credentials;
/// Native RECLAIM service with actual provider/client bindings.
#[cfg(all(feature = "official-reclaim-server", unix))]
pub use gnunet_reclaim_host as reclaim_host;
/// Optional MESSENGER structural codecs and fixed zeroizing message storage.
/// Pure caller-buffer HTTP/REST contracts.
#[cfg(feature = "rest")]
pub use gnunet_rest as rest;
/// Native original-source REST handlers and bounded HTTP owner.
#[cfg(all(feature = "official-rest-server", unix))]
pub use gnunet_rest_host as rest_host;
/// Bounded DNS record conversion and optional allocated online import state.
#[cfg(feature = "zoneimport")]
pub use gnunet_zoneimport_core as zoneimport;
/// Caller-driven DNS-to-NAMESTORE importer with actual native service owners.
#[cfg(all(feature = "official-zoneimport", unix))]
pub use gnunet_zoneimport_host as zoneimport_host;

/// Optional public NAMECACHE block verifier and explicit-alloc ciphertext cache.
#[cfg(feature = "namecache")]
pub use gnunet_namecache as namecache;
/// Optional bounded NAMECACHE SERVICE with actual volatile storage.
#[cfg(all(feature = "official-namecache-server", unix))]
pub use gnunet_namecache_host as namecache_host;

/// Optional opaque IDENTITY keys and explicit-alloc transaction core.
#[cfg(feature = "identity")]
pub use gnunet_identity as identity;
/// Optional IDENTITY service with one explicit durable storage worker.
#[cfg(all(feature = "official-identity-server", unix))]
pub use gnunet_identity_host as identity_host;

/// Official ARM codec and pure client/monitor ownership with explicit native ABI.
pub use gnunet_arm_core as arm;
/// Optional real ARM control/monitor transport and caller-owned local launcher.
#[cfg(all(feature = "official-arm", unix))]
pub use gnunet_arm_host as arm_host;
/// Borrowed ARM server transitions and explicit native effects; host resources are separate.
pub use gnunet_arm_service_core as arm_service;
/// Optional ARM registry, native listeners and standard SERVICE frontend.
#[cfg(all(any(feature = "official-arm", feature = "official-arm-server"), unix))]
pub use gnunet_arm_service_host as arm_service_host;
/// Official BLOCK registry, installed plugins, duplicate groups and proof of work.
pub use gnunet_block as block;
/// Bounded official CADET application channel owner; peer routing is separate.
pub use gnunet_cadet as cadet;
/// Optional caller-driven CADET CLIENT/SERVICE application MQs and inspectors.
#[cfg(all(
    unix,
    any(feature = "official-cadet-client", feature = "official-cadet-server")
))]
pub use gnunet_cadet_host as cadet_host;
/// Official service client protocols.
pub mod clients;
/// Optional shared CLIENT endpoint selection and typed process Resolver effects.
#[cfg(all(feature = "official-client", unix))]
pub use gnunet_client_host as client_host;
/// Optional official host configuration loading and value semantics.
#[cfg(feature = "official-config")]
pub use gnunet_config as config;
/// Official CAKE peer handshake/record engine; a full CORE service host is separate.
pub use gnunet_core as core;
/// Optional caller-driven CORE application and continuous monitor clients.
#[cfg(all(feature = "official-core-client", unix))]
pub use gnunet_core_client_host as core_client_host;
/// Optional official CORE application/monitor and CAKE service host.
#[cfg(all(feature = "official-core", unix))]
pub use gnunet_core_host as core_host;
/// Official cryptographic primitives and signature encodings.
pub use gnunet_crypto as crypto;
/// Allocation-free DATASTORE service decisions over an explicit storage port.
pub use gnunet_datastore as datastore;
/// Optional native official DATASTORE client and independent server/backend.
#[cfg(all(unix, feature = "official-datastore"))]
pub use gnunet_datastore_host as datastore_host;
/// DNS packet names, records and checked encoders with explicit storage and UTC.
pub use gnunet_dns as dns;
/// Raw DNS UDP retry owner with explicit host effects and unverified responses.
pub use gnunet_dnsstub as dnsstub;
/// Optional caller-driven raw DNS UDP host; responses still require validation.
#[cfg(feature = "official-dns")]
pub use gnunet_dnsstub_host as dns_host;
/// Optional EXIT policy/NAT algorithms; forwarding ownership requires exit-alloc.
#[cfg(feature = "exit")]
pub use gnunet_exit as exit;
/// Optional caller-driven EXIT runtime with actual CADET/TUN/DNS effect ports.
#[cfg(all(feature = "official-exit", unix))]
pub use gnunet_exit_host as exit_host;
/// Official pure FS CHK/SKS/KSK/LOC URI artifacts; full file-sharing service is separate.
pub use gnunet_fs as fs;
/// Optional pure Rust metadata inflater; compression requires fs-compression/alloc.
#[cfg(feature = "fs-codec")]
pub use gnunet_fs_codec as fs_codec;
/// Optional native block repository and streaming file/directory host operations.
#[cfg(all(unix, feature = "official-fs"))]
pub use gnunet_fs_host as fs_host;
/// Pure GNS authority and recursive resolver ownership.
pub use gnunet_gns as gns;
/// Official GNS label normalization, zone cryptography and encrypted record blocks.
pub use gnunet_gnscrypto as gnscrypto;
/// Official GNS records and typed zone identifiers.
pub use gnunet_gnsrecord as gnsrecord;
/// Official HELLO address sets, signed metadata, binary formats and URLs.
pub use gnunet_hello as hello;
/// Native DNS text conversion with explicit Unicode/library profiles and scratch.
pub use gnunet_idna as idna;
/// Optional deadline-bounded STATISTICS Unix/TCP service IPC.
#[cfg(all(feature = "official-ipc", unix))]
pub use gnunet_ipc_unix as ipc;
/// Pure NSE service owner, crypto admission and weighted estimation; native hosting is separate.
pub use gnunet_nse as nse;
/// Optional caller-driven NSE host with actual CORE/PILS and fenced raw8 persistence.
#[cfg(all(feature = "official-nse", unix))]
pub use gnunet_nse_host as nse_host;
/// Allocation-free PEERSTORE service with explicit storage and original MQ ownership.
pub use gnunet_peerstore as peerstore;
/// Optional durable PEERSTORE service and explicit bounded storage worker.
#[cfg(all(feature = "official-peerstore-server", unix))]
pub use gnunet_peerstore_host as peerstore_host;
/// Official PILS identity derivation and service decisions with explicit profiles.
pub use gnunet_pils as pils;
/// Optional native PILS host and durable initial-key ownership.
#[cfg(all(feature = "official-pils", unix))]
pub use gnunet_pils_host as pils_host;
/// Optional shared official PROGRAM, GETOPT, logging and locale host primitives.
#[cfg(all(feature = "official-program", unix))]
pub use gnunet_program_host as program;
/// Optional pure REGEX state artifacts and explicit-alloc byte-language compiler.
#[cfg(feature = "regex")]
pub use gnunet_regex as regex;
/// Standard REGEX SERVICE entry with explicit real caller-owned DHT factory.
#[cfg(all(feature = "official-regex-service", unix))]
pub use gnunet_regex_program_host as regex_service_host;
/// Actual optional Unix/TCP REGEX host and PILS/provider coordinator.
#[cfg(all(feature = "official-regex-server", unix))]
pub use gnunet_regex_server_host as regex_server_host;
/// Pure default-noalloc REGEX service artifacts and explicit-alloc owner.
#[cfg(feature = "regex-service")]
pub use gnunet_regex_service as regex_service;
/// One explicit shared process Resolver domain and its unique I/O driver.
#[cfg(all(feature = "official-client", unix))]
pub use gnunet_resolver_broker as resolver_broker;
/// Optional real Unix/TCP/UDP Resolver service host with explicit native ports.
#[cfg(all(feature = "official-resolver", unix))]
pub use gnunet_resolver_host as resolver_host;
/// Source-derived resolver daemon cache/lookup state with explicit borrowed storage.
pub use gnunet_resolver_service_core as resolver_service;
/// Allocation-free resource primitives.
pub use gnunet_resources as resources;
/// Optional service listeners/readiness and the shared native process owner.
#[cfg(all(feature = "official-service", unix))]
pub use gnunet_service_runtime as service_runtime;
/// Optional early process startup primitives; full daemon/control reactor is separate.
#[cfg(all(feature = "official-service", unix))]
pub use gnunet_service_startup as service_startup;
/// Official DHKEM/CAKE traffic and record primitives; handshake admission is separate.
pub use gnunet_session_crypto as session_crypto;
/// Fixed-capacity official STATISTICS service state and effects.
pub use gnunet_statistics as statistics;
/// Optional official STATISTICS disk-format storage and recovery.
#[cfg(feature = "statistics-store")]
pub use gnunet_statistics_store as statistics_store;
/// Official TRANSPORT codecs and optional alloc-backed direct reliable service engine.
pub use gnunet_transport as transport;
/// Optional actual native TRANSPORT monitoring and virtual-link listing client.
#[cfg(all(feature = "official-transport-observation", unix))]
pub use gnunet_transport_application_host::observation as transport_observation;
/// Optional real TRANSPORT service host and owned replay journal.
#[cfg(all(feature = "official-transport", unix))]
pub use gnunet_transport_host as transport_host;
/// Optional verified native TUN ownership and explicit platform configuration.
#[cfg(all(feature = "official-tun", unix))]
pub use gnunet_tun_host as tun;
/// Shared errors, units and internal resource identifiers.
pub use gnunet_types as types;
/// Shared allocation-free official VPN/EXIT IP packet and application port primitives.
pub use gnunet_vpn as vpn;
/// Optional actual VPN IPC SERVICE; native forwarding ports remain caller-owned.
#[cfg(all(feature = "official-vpn-server", unix))]
pub use gnunet_vpn_host as vpn_host;
/// Official GNUnet framing and P2P codecs.
pub use gnunet_wire::official as wire;

/// Official TCP record/session core; full communicator and CORE owners remain pending.
pub use gnunet_tcp_communicator_core as tcp;
/// Optional caller-driven TCP session host with actual official local service IPC.
#[cfg(all(feature = "official-tcp", unix))]
pub use gnunet_tcp_communicator_host as tcp_host;
/// Pure official UDP packet/session protocol; native UDP is a separate adapter.
pub use gnunet_udp_communicator_core as udp;

/// Optional RPS public identity types; actual protocol and sampler owners require rps-alloc.
#[cfg(feature = "rps")]
pub use gnunet_rps as rps;

/// Optional actual RPS SERVICE/CADET host, independent of the native client.
#[cfg(all(feature = "official-rps-server", unix))]
pub use gnunet_rps_host as rps_host;

/// Optional independent finite-work Paillier arithmetic with explicit entropy.
#[cfg(feature = "paillier")]
pub use gnunet_paillier as paillier;

/// Optional actual ABD canonical credential and bounded proof resolution core.
#[cfg(feature = "abd")]
pub use gnunet_abd as abd;

/// Optional official CONSENSUS session and bounded generic-SET gradecast core.
#[cfg(feature = "consensus")]
pub use gnunet_consensus as consensus;

/// Actual original native CONSENSUS service and SET/PILS composition.
#[cfg(all(feature = "official-consensus-server", unix))]
pub use gnunet_consensus_host as consensus_host;

/// Optional actual Paillier scalarproduct math and original session owners.
#[cfg(feature = "scalarproduct-paillier")]
pub use gnunet_scalarproduct_paillier as scalarproduct_paillier;

/// Optional default SCALARPRODUCT ECC computation and explicit bounded CPU jobs.
#[cfg(feature = "scalarproduct")]
pub use gnunet_scalarproduct as scalarproduct;

/// Optional actual ECC/Paillier SCALARPRODUCT IPC/SETI/CADET service owner.
#[cfg(all(feature = "official-scalarproduct-server", unix))]
pub use gnunet_scalarproduct_host as scalarproduct_host;

/// Optional generic SET public types and independent old reconciliation core.
#[cfg(feature = "set")]
pub use gnunet_set as set;

/// Optional actual generic SET SERVICE/CADET host.
#[cfg(all(feature = "official-set-server", unix))]
pub use gnunet_set_host as set_host;

/// Optional SETU caller-storage IBF/strata; operation/service owners require explicit setu-alloc.
#[cfg(feature = "setu")]
pub use gnunet_setu as setu;

/// Allocation-free SETI sets, snapshots and original Bloom-intersection effects.
pub use gnunet_seti as seti;

/// Optional real SETU SERVICE/CADET adapter with explicit source ownership.
#[cfg(all(feature = "official-setu-server", unix))]
pub use gnunet_setu_host as setu_host;

/// Optional SETI SERVICE/CADET adapter with caller-owned fixed storage.
#[cfg(all(feature = "official-seti-server", unix))]
pub use gnunet_seti_host as seti_host;

/// Actual fixed threshold/group arithmetic and original partial-decryption proofs.
/// Fair-equation checking alone does not establish a fair-encryption proof or DKG.
#[cfg(feature = "secretsharing")]
pub use gnunet_secretsharing as secretsharing;

/// Actual native multi-request ABD service over original GNS and PRIVATE NAMESTORE.
#[cfg(all(feature = "official-abd-server", unix))]
pub use gnunet_abd_host as abd_host;

/// Actual conditional per-Line CONVERSATION state and authenticated ringing.
#[cfg(feature = "conversation")]
pub use gnunet_conversation as conversation;

/// Original SECRETSHARING781 decryption over actual PILS and CONSENSUS sources.
/// General fair-encryption, DKG and normal service dispatch are separate work.
#[cfg(all(feature = "official-secretsharing-decrypt", unix))]
pub use gnunet_secretsharing_decrypt_host as secretsharing_decrypt_host;

/// Actual original CONVERSATION IPC service over caller-selected CADET and PILS.
#[cfg(all(feature = "official-conversation-server", unix))]
pub use gnunet_conversation_host as conversation_host;

/// Explicit standard730/Ogg/Opus media helpers and selected native audio provider.
/// Device and blocking process lifetimes belong to the caller.
#[cfg(all(feature = "official-conversation-audio", unix))]
pub use gnunet_conversation_audio_host as conversation_audio_host;

/// Actual native SECRETSHARING first-round key-generation transcript owner.
/// This stage does not produce a final share, FAIR proof or complete DKG.
#[cfg(all(feature = "official-secretsharing-keygen", unix))]
pub use gnunet_secretsharing_keygen_host as secretsharing_keygen_host;

/// Native SECRETSHARING781 service. General780/final783 requires separate FAIR/DKG work.
#[cfg(all(feature = "official-secretsharing-server", unix))]
pub use gnunet_secretsharing_host as secretsharing_host;

/// Shared configured URI argv selection and actual handler-process ownership.
#[cfg(all(feature = "official-uri-dispatch", unix))]
pub use gnunet_uri_host as uri_dispatch;

/// Standard PNG/ZBar image and selected camera provider; no GNUnet C library.
#[cfg(all(feature = "official-qr", unix))]
pub use gnunet_qr_host as qr_host;
