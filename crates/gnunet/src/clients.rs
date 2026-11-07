//! Official service client APIs. Existing sans-I/O modules retain their paths.
pub use gnunet_client::*;
/// Optional IDENTITY monitor, CRUD and independent lookup MQs.
#[cfg(all(feature = "official-identity-client", unix))]
pub use gnunet_identity_client_host as identity;
/// Optional caller-driven NAMECACHE lookup, cache and delete client.
#[cfg(all(feature = "official-namecache-client", unix))]
pub use gnunet_namecache_client_host as namecache;
/// Optional NAMESTORE operations and independent iterator/monitor sources.
#[cfg(all(feature = "official-namestore-client", unix))]
pub use gnunet_namestore_client_host as namestore;
/// Optional native PILS client. `crate::pils::client` remains the pure core.
/// Clock and CLIENT ports are public; no hidden process Resolver is constructed.
#[cfg(all(feature = "official-pils-client", unix))]
pub mod pils {
    pub use gnunet_pils::client::{
        Completion, Epoch, Failure, FeedDisposition, Identity, Inbound, Instance, KeyTarget,
        LocalKeyStatus, LossReport, LostFeed, OperationId, Secret, TransmitId, Written,
    };
    pub use gnunet_pils::{HelloLimits, MasterKey, Profile};
    pub use gnunet_pils_host::client::*;
}

/// Optional caller-driven official DHT local MQ client.
/// Runtime/clock/CLIENT ports stay caller-owned; no Resolver is created here.
/// Results/paths remain unverified, and PUT completion is local writing only.
#[cfg(all(feature = "official-dht-client", unix))]
pub use gnunet_dht_client_host as dht;

/// Official GNS query semantics; the optional native adapter uses explicit
/// CLIENT/clock ports and does not create a Resolver or GNS service.
pub mod gns {
    pub use gnunet_client::gns::*;
    /// Caller-driven native Unix/TCP GNS client with retained original framing.
    #[cfg(all(feature = "official-gns-client", unix))]
    pub mod native {
        pub use gnunet_gns_client_host::*;
    }
}

/// Optional caller-driven PEERSTORE store, iterator and monitor clients.
#[cfg(all(feature = "official-peerstore-client", unix))]
pub use gnunet_peerstore_client_host as peerstore;

/// Optional original-MQ SETI native set and listener clients.
#[cfg(all(feature = "official-seti-client", unix))]
pub use gnunet_seti_client_host as seti;

/// Optional original-MQ RPS view/biased stream and independently sampled requests.
#[cfg(all(feature = "official-rps-client", unix))]
pub use gnunet_rps_client_host as rps;

/// Optional original-MQ SETU native set and listener clients with explicit source ABI.
#[cfg(all(feature = "official-setu-client", unix))]
pub use gnunet_setu_client_host as setu;

/// Optional bounded native VPN allocation client with explicit endpoint AF values.
#[cfg(all(feature = "official-vpn-client", unix))]
pub use gnunet_vpn_client_host as vpn;

/// Optional bounded native REGEX announcement/search clients on original MQs.
#[cfg(all(feature = "official-regex-client", unix))]
pub use gnunet_regex_client_host as regex;

/// Optional original-source RECLAIM requests and independent credited iterators.
#[cfg(all(feature = "official-reclaim-client", unix))]
pub use gnunet_reclaim_client_host as reclaim;

/// Optional original-source MESSENGER frames and asynchronous notifications.
#[cfg(all(feature = "official-messenger-client", unix))]
pub use gnunet_messenger_client_host as messenger;
/// Optional higher-level native MESSENGER client composition and record providers.
#[cfg(all(feature = "official-messenger-api", unix))]
pub use gnunet_messenger_host as messenger_api;
/// Optional single-operation original REVOCATION MQ client.
#[cfg(all(feature = "official-revocation-client", unix))]
pub use gnunet_revocation_client_host as revocation;

/// Optional DID composition over actual IDENTITY, NAMESTORE and GNS clients.
#[cfg(all(feature = "official-did-client", unix))]
pub use gnunet_did_host as did;

/// Optional original-MQ NAT registration and independent NAT-auto query clients.
#[cfg(all(feature = "official-nat-client", unix))]
pub use gnunet_nat_client_host as nat;

/// Optional original-source NAT test caller with actual listener/challenge observations.
#[cfg(all(feature = "official-nat-test", unix))]
pub use gnunet_nat_test_host as nat_test;

/// Optional original-MQ DNS interception callbacks and decisions, separate from DNSSTUB.
#[cfg(all(feature = "official-dns-client", unix))]
pub use gnunet_dns_client_host as dns;

/// Official allocation-free NSE subscription state, with an optional native owner.
pub mod nse {
    pub use gnunet_client::nse::*;
    /// Original-MQ native subscription; uses explicit CLIENT/clock/Resolver ports.
    #[cfg(all(feature = "official-nse-client", unix))]
    pub mod native {
        pub use gnunet_nse_client_host::*;
    }
}

/// Native active generic SET caller, distinct from SETI/SETU.
#[cfg(all(unix, feature = "official-set-client"))]
pub use gnunet_set_client_host as set;

/// Native official scalarproduct requester/responder caller.
#[cfg(all(unix, feature = "official-scalarproduct-client"))]
pub use gnunet_scalarproduct_client_host as scalarproduct;

/// Optional actual native CONSENSUS caller with original JOIN/INSERT/CONCLUDE receipts.
#[cfg(all(feature = "official-consensus-client", unix))]
pub use gnunet_consensus_client_host as consensus;

/// Optional actual native ABD caller with original RID/write/result/loss ownership.
#[cfg(all(feature = "official-abd-client", unix))]
pub use gnunet_abd_client_host as abd;

/// Optional original-MQ threshold-share generation/decryption caller.
/// Actual private shares are zeroizing; raw success is no mathematical proof.
#[cfg(all(feature = "official-secretsharing-client", unix))]
pub use gnunet_secretsharing_client_host as secretsharing;

/// Original CONVERSATION Line, call identities and bounded opaque audio ownership.
#[cfg(all(feature = "official-conversation-client", unix))]
pub use gnunet_conversation_client_host as conversation;
