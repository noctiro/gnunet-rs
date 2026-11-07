//! Dependency, feature, lint and resolved no-allocation architecture guards.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
    process::Command,
};

type CheckResult<T> = Result<T, Box<dyn Error>>;

struct Policy {
    name: &'static str,
    directory: &'static str,
    core: bool,
    dependencies: &'static [&'static str],
}

const POLICIES: &[Policy] = &[
    Policy {
        name: "gnunet-directory-command",
        directory: "apps/gnunet-directory",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-fs",
            "gnunet-fs-codec",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-base32-command",
        directory: "apps/gnunet-base32",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-gnsrecord",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-scrypt-command",
        directory: "apps/gnunet-scrypt",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-nse",
            "gnunet-nse-host",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-ecc-command",
        directory: "apps/gnunet-ecc",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-session-crypto",
            "gnunet-types",
            "libc",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-bcd-host",
        directory: "adapters/bcd-std",
        core: false,
        dependencies: &[
            "bytes",
            "gnunet-config",
            "gnunet-gnsrecord",
            "gnunet-service-runtime",
            "gnunet-types",
            "http-body-util",
            "hyper",
            "hyper-util",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-bcd-command",
        directory: "apps/gnunet-bcd",
        core: false,
        dependencies: &[
            "gnunet-bcd-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-extractor-host",
        directory: "adapters/extractor-std",
        core: false,
        dependencies: &["libc"],
    },
    Policy {
        name: "gnunet-secretsharing-host",
        directory: "adapters/secretsharing-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client-host",
            "gnunet-consensus-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-secretsharing",
            "gnunet-secretsharing-decrypt-host",
            "gnunet-secretsharing-keygen-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-secretsharing",
        directory: "apps/gnunet-service-secretsharing",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-pils",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-secretsharing-decrypt-host",
            "gnunet-secretsharing-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-uri-host",
        directory: "adapters/uri-std",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-qr-host",
        directory: "adapters/qr-std",
        core: false,
        dependencies: &["gnunet-types", "libc"],
    },
    Policy {
        name: "gnunet-qr-command",
        directory: "apps/gnunet-qr",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-qr-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-uri-host",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-conversation-command",
        directory: "apps/gnunet-conversation",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-conversation-client-host",
            "gnunet-crypto",
            "gnunet-gns-client-host",
            "gnunet-gns-host",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "gnunet-identity",
            "gnunet-identity-client-host",
            "gnunet-idna",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-secretsharing-keygen-host",
        directory: "adapters/secretsharing-keygen-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client-host",
            "gnunet-consensus-client-host",
            "gnunet-crypto",
            "gnunet-paillier",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-secretsharing",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-conversation-host",
        directory: "adapters/conversation-std",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-conversation",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-conversation",
        directory: "apps/gnunet-service-conversation",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-conversation-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-conversation-audio-host",
        directory: "adapters/conversation-audio-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-types",
            "gnunet-wire",
            "libc",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-helper-audio-command",
        directory: "apps/gnunet-helper-audio",
        core: false,
        dependencies: &["gnunet-conversation-audio-host"],
    },
    Policy {
        name: "gnunet-conversation-client-host",
        directory: "adapters/conversation-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-identity",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-secretsharing-decrypt-host",
        directory: "adapters/secretsharing-decrypt-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client-host",
            "gnunet-consensus-client-host",
            "gnunet-crypto",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-secretsharing",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-conversation",
        directory: "crates/gnunet-conversation",
        core: true,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-identity",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-secretsharing-client-host",
        directory: "adapters/secretsharing-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-abd-command",
        directory: "apps/gnunet-abd",
        core: false,
        dependencies: &[
            "gnunet-abd",
            "gnunet-abd-client-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "gnunet-identity",
            "gnunet-identity-client-host",
            "gnunet-idna",
            "gnunet-namestore-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "subtle",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-abd-host",
        directory: "adapters/abd-std",
        core: false,
        dependencies: &[
            "gnunet-abd",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-gns-client-host",
            "gnunet-namestore-client-host",
            "gnunet-identity",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-abd",
        directory: "apps/gnunet-service-abd",
        core: false,
        dependencies: &[
            "gnunet-abd",
            "gnunet-abd-host",
            "gnunet-client-host",
            "gnunet-gns-client-host",
            "gnunet-namestore-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-secretsharing",
        directory: "crates/gnunet-secretsharing",
        core: true,
        dependencies: &[
            "crypto-bigint",
            "zeroize",
            "gnunet-crypto",
            "gnunet-paillier",
            "gnunet-types",
            "gnunet-wire",
        ],
    },
    Policy {
        name: "gnunet-consensus-host",
        directory: "adapters/consensus-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-pils-host",
            "gnunet-consensus",
            "gnunet-pils",
            "gnunet-set-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-consensus",
        directory: "apps/gnunet-service-consensus",
        core: false,
        dependencies: &[
            "gnunet-consensus",
            "gnunet-consensus-host",
            "gnunet-client-host",
            "gnunet-set-client-host",
            "gnunet-pils-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-abd-client-host",
        directory: "adapters/abd-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-scalarproduct-host",
        directory: "adapters/scalarproduct-std",
        core: false,
        dependencies: &[
            "gnunet-paillier",
            "gnunet-scalarproduct-paillier",
            "gnunet-scalarproduct",
            "gnunet-cadet-host",
            "gnunet-seti-client-host",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "getrandom",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-scalarproduct",
        directory: "apps/gnunet-service-scalarproduct",
        core: false,
        dependencies: &[
            "gnunet-scalarproduct-paillier",
            "gnunet-scalarproduct",
            "gnunet-scalarproduct-host",
            "gnunet-cadet-host",
            "gnunet-seti-client-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-scalarproduct-client-host",
        directory: "adapters/scalarproduct-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-scalarproduct-command",
        directory: "apps/gnunet-scalarproduct",
        core: false,
        dependencies: &[
            "gnunet-scalarproduct-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-program-host",
            "gnunet-client-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "num-bigint",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-compression",
        directory: "crates/gnunet-compression",
        core: true,
        dependencies: &["gnunet-types", "miniz_oxide"],
    },
    Policy {
        name: "gnunet-set-client-host",
        directory: "adapters/set-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-abd",
        directory: "crates/gnunet-abd",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-identity",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-consensus-client-host",
        directory: "adapters/consensus-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-consensus",
        directory: "crates/gnunet-consensus",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-crypto"],
    },
    Policy {
        name: "gnunet-scalarproduct-paillier",
        directory: "crates/gnunet-scalarproduct-paillier",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-paillier",
            "gnunet-scalarproduct",
            "crypto-bigint",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-paillier",
        directory: "crates/gnunet-paillier",
        core: true,
        dependencies: &["gnunet-crypto", "gnunet-types", "crypto-bigint", "zeroize"],
    },
    Policy {
        name: "gnunet-scalarproduct",
        directory: "crates/gnunet-scalarproduct",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "curve25519-dalek",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-set",
        directory: "crates/gnunet-set",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-block",
        ],
    },
    Policy {
        name: "gnunet-set-host",
        directory: "adapters/set-std",
        core: false,
        dependencies: &[
            "gnunet-set",
            "gnunet-cadet-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-compression",
            "getrandom",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-set",
        directory: "apps/gnunet-service-set",
        core: false,
        dependencies: &[
            "gnunet-set",
            "gnunet-set-host",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-rps",
        directory: "crates/gnunet-rps",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "zeroize"],
    },
    Policy {
        name: "gnunet-rps-host",
        directory: "adapters/rps-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-cadet-host",
            "gnunet-crypto",
            "gnunet-rps",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-rps-client-host",
        directory: "adapters/rps-client-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-rps",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-rps",
        directory: "apps/gnunet-service-rps",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-core-client-host",
            "gnunet-nse-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-rps",
            "gnunet-rps-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-rps-command",
        directory: "apps/gnunet-rps",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-rps-client-host",
            "gnunet-service-runtime",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-messenger-command",
        directory: "apps/gnunet-messenger",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-identity-client-host",
            "gnunet-messenger-host",
            "gnunet-namestore-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-datastore-command",
        directory: "apps/gnunet-datastore",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-datastore-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-namecache-cli",
        directory: "apps/gnunet-namecache",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-gnscrypto",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "gnunet-idna",
            "gnunet-namecache-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-auto-share",
        directory: "apps/gnunet-auto-share",
        core: false,
        dependencies: &[
            "gnunet-fs-host",
            "gnunet-config",
            "gnunet-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-arm",
        directory: "apps/gnunet-service-arm",
        core: false,
        dependencies: &[
            "gnunet-arm-service-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
        ],
    },
    Policy {
        name: "gnunet-quic-communicator-host",
        directory: "adapters/quic-communicator-std",
        core: false,
        dependencies: &[
            "bytes",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-hello",
            "gnunet-nat-client-host",
            "gnunet-native",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-transport-quic",
            "gnunet-types",
            "gnunet-wire",
            "h3",
            "h3-quinn",
            "http",
            "libc",
            "quinn",
            "rcgen",
            "rustls",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-communicator-quic",
        directory: "apps/gnunet-communicator-quic",
        core: false,
        dependencies: &[
            "gnunet-quic-communicator-host",
            "gnunet-service-startup",
            "gnunet-ipc-unix",
        ],
    },
    Policy {
        name: "gnunet-communicator-http3",
        directory: "apps/gnunet-communicator-http3",
        core: false,
        dependencies: &[
            "gnunet-quic-communicator-host",
            "gnunet-service-startup",
            "gnunet-ipc-unix",
        ],
    },
    Policy {
        name: "gnunet-transport-quic",
        directory: "crates/gnunet-transport-quic",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "zeroize"],
    },
    Policy {
        name: "gnunet-transport-dv-bridge-host",
        directory: "adapters/transport-dv-bridge-std",
        core: false,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-service-runtime",
            "gnunet-transport",
            "gnunet-transport-host",
            "gnunet-transport-dv-runtime-host",
            "gnunet-transport-dv-store-host",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-transport-dv-runtime-host",
        directory: "adapters/transport-dv-runtime-std",
        core: false,
        dependencies: &[
            "gnunet-transport",
            "gnunet-transport-dv-crypto",
            "gnunet-transport-dv-crypto-host",
            "gnunet-transport-dv-store-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-wire",
            "gnunet-types",
            "gnunet-crypto",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-transport-dv-store-host",
        directory: "adapters/transport-dv-store-std",
        core: false,
        dependencies: &[
            "gnunet-service-runtime",
            "tokio",
            "gnunet-snapshot-host",
            "gnunet-transport",
            "gnunet-transport-dv-crypto",
            "gnunet-types",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-transport",
        directory: "apps/gnunet-service-transport",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-transport-service-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-transport-dv-crypto",
        directory: "crates/gnunet-transport-dv-crypto",
        core: true,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-session-crypto",
            "gnunet-transport",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-transport-dv-crypto-host",
        directory: "adapters/transport-dv-crypto-std",
        core: false,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-transport",
            "gnunet-transport-dv-crypto",
            "gnunet-types",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-unix-communicator",
        directory: "crates/gnunet-unix-communicator",
        core: true,
        dependencies: &["gnunet-transport", "gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-unix-communicator-host",
        directory: "adapters/unix-communicator-std",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-unix-communicator",
            "gnunet-wire",
            "libc",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-communicator-unix",
        directory: "apps/gnunet-communicator-unix",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-pils",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-unix-communicator-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-peer-tools-host",
        directory: "adapters/peer-tools-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-hello",
            "gnunet-peerstore-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-hello-cli",
        directory: "apps/gnunet-hello",
        core: false,
        dependencies: &["gnunet-peer-tools-host"],
    },
    Policy {
        name: "gnunet-pils-cli",
        directory: "apps/gnunet-pils",
        core: false,
        dependencies: &["gnunet-peer-tools-host"],
    },
    Policy {
        name: "gnunet-transport-service-host",
        directory: "adapters/transport-service-std",
        core: false,
        dependencies: &[
            "gnunet-transport-dv-bridge-host",
            "gnunet-transport-dv-store-host",
            "gnunet-transport-dv-crypto",
            "gnunet-transport-dv-runtime-host",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-ipc-unix",
            "gnunet-nat-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-snapshot-host",
            "gnunet-transport",
            "gnunet-transport-host",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-nse-client-host",
        directory: "adapters/nse-client-std",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nse-command",
        directory: "apps/gnunet-nse",
        core: false,
        dependencies: &[
            "gnunet-nse-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-core-cli",
        directory: "apps/gnunet-core",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-core-client-host",
            "gnunet-client-host",
            "gnunet-types",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-zonemaster",
        directory: "apps/gnunet-service-zonemaster",
        core: false,
        dependencies: &[
            "gnunet-zonemaster-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-dns-tools-host",
        directory: "adapters/dns-tools-std",
        core: false,
        dependencies: &[
            "gnunet-dns",
            "gnunet-dns-client-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-dns-monitor",
        directory: "apps/gnunet-dns-monitor",
        core: false,
        dependencies: &["gnunet-dns-tools-host"],
    },
    Policy {
        name: "gnunet-dns-redirector",
        directory: "apps/gnunet-dns-redirector",
        core: false,
        dependencies: &["gnunet-dns-tools-host"],
    },
    Policy {
        name: "gnunet-dns-interception",
        directory: "crates/gnunet-dns-interception",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-dns",
            "gnunet-vpn",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-dns-service-host",
        directory: "adapters/dns-service-std",
        core: false,
        dependencies: &[
            "gnunet-dns-interception",
            "gnunet-dnsstub-host",
            "gnunet-service-runtime",
            "gnunet-tun-host",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-vpn",
            "nix",
            "tokio",
            "libc",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-dns",
        directory: "apps/gnunet-service-dns",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-ipc-unix",
            "gnunet-config",
            "gnunet-dns-interception",
            "gnunet-dns-service-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-helper-dns",
        directory: "apps/gnunet-helper-dns",
        core: false,
        dependencies: &["gnunet-dns-service-host", "tokio"],
    },
    Policy {
        name: "gnunet-http-host",
        directory: "adapters/http-std",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-native",
            "tokio",
            "zeroize",
            "hyper",
            "hyper-util",
            "http-body-util",
            "bytes",
            "tokio-rustls",
            "rustls",
            "webpki-roots",
            "url",
        ],
    },
    Policy {
        name: "gnunet-hostlist",
        directory: "crates/gnunet-hostlist",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-hello", "zeroize"],
    },
    Policy {
        name: "gnunet-hostlist-host",
        directory: "adapters/hostlist-std",
        core: false,
        dependencies: &[
            "gnunet-http-host",
            "gnunet-hostlist",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-hello",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-core-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-service-runtime",
            "gnunet-snapshot-host",
            "gnunet-config",
            "gnunet-native",
            "tokio",
            "zeroize",
            "hyper",
            "hyper-util",
            "http-body-util",
            "bytes",
            "url",
        ],
    },
    Policy {
        name: "gnunet-daemon-hostlist",
        directory: "apps/gnunet-daemon-hostlist",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-hostlist",
            "gnunet-hostlist-host",
            "gnunet-core-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-client-host",
            "gnunet-snapshot-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-hello",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-zonemaster",
        directory: "crates/gnunet-zonemaster",
        core: true,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-gnscrypto",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "gnunet-identity",
            "gnunet-namestore",
            "gnunet-types",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-zonemaster-host",
        directory: "adapters/zonemaster-std",
        core: false,
        dependencies: &[
            "gnunet-zonemaster",
            "gnunet-types",
            "gnunet-snapshot-host",
            "zeroize",
            "gnunet-identity",
            "gnunet-gnsrecord-text",
            "gnunet-wire",
            "gnunet-client-host",
            "gnunet-native",
            "gnunet-namestore-client-host",
            "gnunet-namecache-client-host",
            "gnunet-dht-client-host",
            "gnunet-service-runtime",
            "gnunet-config",
            "gnunet-service-startup",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-ipc-unix",
            "gnunet-client",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-pt-host",
        directory: "adapters/pt-std",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-ipc-unix",
            "gnunet-pt",
            "gnunet-dns-client-host",
            "gnunet-vpn-client-host",
            "gnunet-cadet-host",
            "gnunet-dht-client-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-dns",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-daemon-pt",
        directory: "apps/gnunet-daemon-pt",
        core: false,
        dependencies: &[
            "gnunet-pt-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-testbed",
        directory: "crates/gnunet-testbed",
        core: true,
        dependencies: &["gnunet-types"],
    },
    Policy {
        name: "gnunet-testbed-host",
        directory: "adapters/testbed-std",
        core: false,
        dependencies: &[
            "gnunet-testbed",
            "gnunet-config",
            "gnunet-types",
            "socket2",
            "libc",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-testbed-tool",
        directory: "apps/gnunet-testbed",
        core: false,
        dependencies: &[
            "gnunet-testbed-host",
            "gnunet-program-host",
            "gnunet-config",
            "gnunet-types",
        ],
    },
    Policy {
        name: "gnunet-pt",
        directory: "crates/gnunet-pt",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-dns", "gnunet-crypto"],
    },
    Policy {
        name: "gnunet-dns-client-host",
        directory: "adapters/dns-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-test-host",
        directory: "adapters/nat-test-std",
        core: false,
        dependencies: &[
            "gnunet-nat-client-host",
            "gnunet-nat-host",
            "gnunet-nat",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "getrandom",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-cli",
        directory: "apps/gnunet-nat",
        core: false,
        dependencies: &[
            "gnunet-nat-test-host",
            "gnunet-config",
            "gnunet-program-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-auto-cli",
        directory: "apps/gnunet-nat-auto",
        core: false,
        dependencies: &[
            "gnunet-nat-test-host",
            "gnunet-config",
            "gnunet-program-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-burst-host",
        directory: "adapters/nat-burst-std",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-nat",
            "gnunet-service-runtime",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-nat",
        directory: "apps/gnunet-service-nat",
        core: false,
        dependencies: &[
            "gnunet-nat-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-nat-auto",
        directory: "apps/gnunet-service-nat-auto",
        core: false,
        dependencies: &[
            "gnunet-nat-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-server",
        directory: "apps/gnunet-nat-server",
        core: false,
        dependencies: &[
            "gnunet-nat-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nat-client-host",
        directory: "adapters/nat-client-std",
        core: false,
        dependencies: &[
            "gnunet-wire",
            "gnunet-types",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-config",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-nat",
        directory: "crates/gnunet-nat",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-nat-host",
        directory: "adapters/nat-std",
        core: false,
        dependencies: &[
            "gnunet-http-host",
            "gnunet-nat",
            "gnunet-wire",
            "gnunet-types",
            "gnunet-native",
            "gnunet-config",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-startup",
            "tokio",
            "getrandom",
            "socket2",
            "quick-xml",
        ],
    },
    Policy {
        name: "gnunet-nat-helper-host",
        directory: "adapters/nat-helper-std",
        core: false,
        dependencies: &[
            "gnunet-nat",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-native",
            "socket2",
            "nix",
        ],
    },
    Policy {
        name: "gnunet-helper-nat-client",
        directory: "apps/gnunet-helper-nat-client",
        core: false,
        dependencies: &["gnunet-nat-helper-host"],
    },
    Policy {
        name: "gnunet-helper-nat-server",
        directory: "apps/gnunet-helper-nat-server",
        core: false,
        dependencies: &["gnunet-nat-helper-host"],
    },
    Policy {
        name: "gnunet-helper-vpn",
        directory: "apps/gnunet-helper-vpn",
        core: false,
        dependencies: &["gnunet-tun-helper-host"],
    },
    Policy {
        name: "gnunet-uri",
        directory: "apps/gnunet-uri",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-uri-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-helper-exit",
        directory: "apps/gnunet-helper-exit",
        core: false,
        dependencies: &["gnunet-tun-helper-host"],
    },
    Policy {
        name: "gnunet-tun-helper-host",
        directory: "adapters/tun-helper-std",
        core: false,
        dependencies: &["gnunet-native", "gnunet-types", "gnunet-wire", "libc"],
    },
    Policy {
        name: "gnunet-topology",
        directory: "crates/gnunet-topology",
        core: true,
        dependencies: &["gnunet-hello", "gnunet-types"],
    },
    Policy {
        name: "gnunet-topology-host",
        directory: "adapters/topology-std",
        core: false,
        dependencies: &[
            "gnunet-topology",
            "gnunet-types",
            "gnunet-hello",
            "gnunet-wire",
            "gnunet-transport",
            "gnunet-core-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-pils-host",
            "gnunet-pils",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-daemon-topology",
        directory: "apps/gnunet-daemon-topology",
        core: false,
        dependencies: &[
            "gnunet-ipc-unix",
            "gnunet-client",
            "gnunet-types",
            "gnunet-config",
            "gnunet-topology-host",
            "gnunet-hello",
            "gnunet-core-client-host",
            "gnunet-pils",
            "gnunet-peerstore-client-host",
            "gnunet-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-revocation-client-host",
        directory: "adapters/revocation-client-std",
        core: false,
        dependencies: &[
            "gnunet-revocation",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-revocation-host",
        directory: "adapters/revocation-std",
        core: false,
        dependencies: &[
            "gnunet-revocation",
            "gnunet-block",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-client-host",
            "gnunet-core-client-host",
            "gnunet-setu-client-host",
            "gnunet-snapshot-host",
            "gnunet-service-runtime",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-revocation",
        directory: "apps/gnunet-service-revocation",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-ipc-unix",
            "gnunet-client",
            "gnunet-config",
            "gnunet-revocation",
            "gnunet-revocation-host",
            "gnunet-core-client-host",
            "gnunet-setu-client-host",
            "gnunet-snapshot-host",
            "gnunet-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-messenger-host",
        directory: "adapters/messenger-api-std",
        core: false,
        dependencies: &[
            "gnunet-messenger-core",
            "gnunet-messenger",
            "gnunet-messenger-client-host",
            "gnunet-namestore-client-host",
            "gnunet-gns-client-host",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "subtle",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-crypto",
            "gnunet-identity",
            "gnunet-types",
            "gnunet-wire",
            "getrandom",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-messenger-service-host",
        directory: "adapters/messenger-std",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-messenger-core",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-snapshot-host",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-messenger",
        directory: "apps/gnunet-service-messenger",
        core: false,
        dependencies: &[
            "gnunet-ipc-unix",
            "gnunet-client-host",
            "gnunet-types",
            "gnunet-client",
            "gnunet-config",
            "gnunet-messenger-service-host",
            "gnunet-pils",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-rest",
        directory: "crates/gnunet-rest",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-gnsrecord",
            "gnunet-json",
            "gnunet-reclaim",
            "gnunet-crypto",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-oidc-crypto-host",
        directory: "adapters/oidc-crypto-std",
        core: false,
        dependencies: &[
            "aws-lc-rs",
            "gnunet-types",
            "gnunet-json",
            "gnunet-crypto",
            "gnunet-rest",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-rest-host",
        directory: "adapters/rest-std",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-gns-client-host",
            "gnunet-snapshot-host",
            "gnunet-oidc-crypto-host",
            "nix",
            "libc",
            "gnunet-rest",
            "gnunet-types",
            "gnunet-json",
            "gnunet-wire",
            "gnunet-gnsrecord",
            "gnunet-gnsrecord-text",
            "gnunet-dns",
            "gnunet-identity",
            "gnunet-identity-client-host",
            "gnunet-namestore-client-host",
            "gnunet-reclaim",
            "gnunet-reclaim-client-host",
            "gnunet-reclaim-credentials",
            "gnunet-crypto",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "tokio",
            "zeroize",
            "getrandom",
        ],
    },
    Policy {
        name: "gnunet-rest-server",
        directory: "apps/gnunet-rest-server",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-rest",
            "gnunet-oidc-crypto-host",
            "getrandom",
            "gnunet-rest-host",
            "gnunet-idna",
            "gnunet-gnsrecord-text",
            "gnunet-identity-client-host",
            "gnunet-namestore-client-host",
            "gnunet-reclaim-client-host",
            "gnunet-client-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
            "zeroize",
            "uzers",
            "nix",
            "libc",
        ],
    },
    Policy {
        name: "gnunet-reclaim-host",
        directory: "adapters/reclaim-std",
        core: false,
        dependencies: &[
            "gnunet-ipc-unix",
            "gnunet-client",
            "gnunet-reclaim",
            "gnunet-reclaim-credentials",
            "gnunet-client-host",
            "gnunet-gns-client-host",
            "gnunet-namestore-client-host",
            "gnunet-identity",
            "gnunet-gnsrecord",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-reclaim",
        directory: "apps/gnunet-service-reclaim",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-config",
            "gnunet-reclaim",
            "gnunet-reclaim-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-resolver-command",
        directory: "apps/gnunet-resolver",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-cadet-command",
        directory: "apps/gnunet-cadet",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "nix",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-zoneimport-host",
        directory: "adapters/zoneimport-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-dns",
            "gnunet-dnsstub-host",
            "gnunet-gnsrecord",
            "gnunet-identity-client-host",
            "gnunet-idna",
            "gnunet-namestore-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-zoneimport-core",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-zoneimport",
        directory: "apps/gnunet-zoneimport",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-wire",
            "gnunet-zoneimport-host",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-zoneimport-core",
        directory: "crates/gnunet-zoneimport-core",
        core: true,
        dependencies: &[
            "gnunet-dns",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-wire",
        ],
    },
    Policy {
        name: "gnunet-gnsrecord-text",
        directory: "crates/gnunet-gnsrecord-text",
        core: true,
        dependencies: &[
            "gnunet-dns",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "gnunet-idna",
        ],
    },
    Policy {
        name: "gnunet-messenger-client-host",
        directory: "adapters/messenger-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-json",
        directory: "crates/gnunet-json",
        core: true,
        dependencies: &["gnunet-types", "zeroize"],
    },
    Policy {
        name: "gnunet-reclaim-credentials",
        directory: "crates/gnunet-reclaim-credentials",
        core: true,
        dependencies: &[
            "gnunet-json",
            "gnunet-reclaim",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "gnunet-identity",
        ],
    },
    Policy {
        name: "gnunet-reclaim-client-host",
        directory: "adapters/reclaim-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-reclaim",
            "gnunet-gnsrecord",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-revocation",
        directory: "crates/gnunet-revocation",
        core: true,
        dependencies: &[
            "gnunet-block",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-wire",
        ],
    },
    Policy {
        name: "gnunet-did",
        directory: "crates/gnunet-did",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-gnsrecord",
            "gnunet-json",
            "base64ct",
        ],
    },
    Policy {
        name: "gnunet-did-host",
        directory: "adapters/did-std",
        core: false,
        dependencies: &[
            "gnunet-did",
            "gnunet-json",
            "gnunet-identity-client-host",
            "gnunet-namestore-client-host",
            "gnunet-gns-client-host",
            "gnunet-client-host",
            "gnunet-gnsrecord",
            "gnunet-crypto",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-messenger-core",
        directory: "crates/gnunet-messenger-core",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-messenger",
            "gnunet-identity",
            "subtle",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-messenger",
        directory: "crates/gnunet-messenger",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "gnunet-identity",
            "subtle",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-namestore-host",
        directory: "adapters/namestore-std",
        core: false,
        dependencies: &[
            "gnunet-namestore",
            "gnunet-snapshot-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-namestore",
        directory: "apps/gnunet-service-namestore",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-namestore",
            "gnunet-namestore-host",
            "gnunet-snapshot-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-reclaim",
        directory: "crates/gnunet-reclaim",
        core: true,
        dependencies: &["gnunet-gnsrecord", "gnunet-types", "gnunet-wire", "zeroize"],
    },
    Policy {
        name: "gnunet-namestore",
        directory: "crates/gnunet-namestore",
        core: true,
        dependencies: &[
            "gnunet-gnsrecord",
            "gnunet-idna",
            "gnunet-identity",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-namestore-client-host",
        directory: "adapters/namestore-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-identity",
            "gnunet-gnsrecord",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-datacache",
        directory: "crates/gnunet-datacache",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-namecache-host",
        directory: "adapters/namecache-std",
        core: false,
        dependencies: &[
            "gnunet-namecache",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-namecache",
        directory: "apps/gnunet-service-namecache",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-namecache",
            "gnunet-namecache-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-namecache",
        directory: "crates/gnunet-namecache",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-gnscrypto"],
    },
    Policy {
        name: "gnunet-namecache-client-host",
        directory: "adapters/namecache-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-namecache",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-identity",
        directory: "crates/gnunet-identity",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-idna",
            "zeroize",
            "subtle",
        ],
    },
    Policy {
        name: "gnunet-identity-client-host",
        directory: "adapters/identity-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-crypto",
            "gnunet-identity",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-snapshot-host",
        directory: "adapters/snapshot-std",
        core: false,
        dependencies: &[
            "gnunet-native",
            "gnunet-crypto",
            "gnunet-types",
            "libc",
            "nix",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-identity-host",
        directory: "adapters/identity-std",
        core: false,
        dependencies: &[
            "gnunet-identity",
            "gnunet-snapshot-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-identity",
        directory: "apps/gnunet-service-identity",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-identity",
            "gnunet-identity-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-regex",
        directory: "crates/gnunet-regex",
        core: true,
        dependencies: &["gnunet-types", "gnunet-crypto", "gnunet-block"],
    },
    Policy {
        name: "gnunet-regex-service",
        directory: "crates/gnunet-regex-service",
        core: true,
        dependencies: &[
            "gnunet-regex",
            "gnunet-crypto",
            "gnunet-types",
            "gnunet-wire",
        ],
    },
    Policy {
        name: "gnunet-regex-server-host",
        directory: "adapters/regex-std",
        core: false,
        dependencies: &[
            "gnunet-dht-client-host",
            "gnunet-regex-service",
            "gnunet-regex",
            "gnunet-crypto",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-regex-program-host",
        directory: "adapters/regex-program-std",
        core: false,
        dependencies: &[
            "gnunet-dht-client-host",
            "gnunet-regex-server-host",
            "gnunet-regex-service",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-service-startup",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-resolver-broker",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-ipc-unix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-regex",
        directory: "apps/gnunet-service-regex",
        core: false,
        dependencies: &["gnunet-regex-program-host"],
    },
    Policy {
        name: "gnunet-regex-client-host",
        directory: "adapters/regex-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-vpn",
        directory: "apps/gnunet-service-vpn",
        core: false,
        dependencies: &[
            "gnunet-regex-client-host",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-tun-host",
            "gnunet-types",
            "gnunet-vpn",
            "gnunet-vpn-host",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-vpn-host",
        directory: "adapters/vpn-std",
        core: false,
        dependencies: &[
            "gnunet-cadet-host",
            "gnunet-tun-host",
            "gnunet-vpn",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-daemon-exit",
        directory: "apps/gnunet-daemon-exit",
        core: false,
        dependencies: &[
            "gnunet-dht-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-pt",
            "gnunet-wire",
            "gnunet-regex-client-host",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-exit",
            "gnunet-exit-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-tun-host",
            "gnunet-types",
            "gnunet-vpn",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-exit-host",
        directory: "adapters/exit-std",
        core: false,
        dependencies: &[
            "gnunet-cadet",
            "gnunet-exit",
            "gnunet-vpn",
            "gnunet-cadet-host",
            "gnunet-tun-host",
            "gnunet-service-runtime",
            "gnunet-dns",
            "gnunet-crypto",
            "gnunet-types",
            "gnunet-wire",
            "getrandom",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-vpn",
        directory: "crates/gnunet-vpn",
        core: true,
        dependencies: &["gnunet-crypto", "gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-exit",
        directory: "crates/gnunet-exit",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-vpn"],
    },
    Policy {
        name: "gnunet-tun-host",
        directory: "adapters/tun-std",
        core: false,
        dependencies: &["libc", "nix", "socket2", "tokio"],
    },
    Policy {
        name: "gnunet-vpn-client-host",
        directory: "adapters/vpn-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-seti-host",
        directory: "adapters/seti-std",
        core: false,
        dependencies: &[
            "gnunet-cadet",
            "gnunet-cadet-host",
            "gnunet-crypto",
            "gnunet-service-runtime",
            "gnunet-seti",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-seti",
        directory: "apps/gnunet-service-seti",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-crypto",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-seti",
            "gnunet-seti-host",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-setu-host",
        directory: "adapters/setu-std",
        core: false,
        dependencies: &[
            "gnunet-setu",
            "gnunet-cadet-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-setu",
        directory: "apps/gnunet-service-setu",
        core: false,
        dependencies: &[
            "gnunet-setu",
            "gnunet-setu-host",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-seti",
        directory: "crates/gnunet-seti",
        core: true,
        dependencies: &[
            "gnunet-block",
            "gnunet-crypto",
            "gnunet-types",
            "gnunet-wire",
        ],
    },
    Policy {
        name: "gnunet-setu",
        directory: "crates/gnunet-setu",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "libm",
            "gnunet-compression",
        ],
    },
    Policy {
        name: "gnunet-setu-client-host",
        directory: "adapters/setu-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-seti-client-host",
        directory: "adapters/seti-client-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-peerstore",
        directory: "crates/gnunet-peerstore",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-peerstore-host",
        directory: "adapters/peerstore-std",
        core: false,
        dependencies: &[
            "gnunet-peerstore",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "getrandom",
            "libc",
            "sha2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-peerstore-client-host",
        directory: "adapters/peerstore-client-std",
        core: false,
        dependencies: &[
            "gnunet-hello",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-peerstore",
        directory: "apps/gnunet-service-peerstore",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-config",
            "gnunet-hello",
            "gnunet-peerstore",
            "gnunet-peerstore-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-pils",
        directory: "apps/gnunet-service-pils",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-cadet",
        directory: "apps/gnunet-service-cadet",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "getrandom",
            "gnunet-crypto",
            "gnunet-core-client-host",
            "gnunet-dht",
            "gnunet-dht-client-host",
            "gnunet-hello",
            "gnunet-cadet",
            "gnunet-cadet-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-transport-application-host",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-cadet-host",
        directory: "adapters/cadet-std",
        core: false,
        dependencies: &[
            "libc",
            "socket2",
            "gnunet-cadet",
            "zeroize",
            "gnunet-session-crypto",
            "gnunet-pils-host",
            "gnunet-pils",
            "gnunet-core-client-host",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "gnunet-fs",
            "gnunet-crypto",
        ],
    },
    Policy {
        name: "gnunet-cadet",
        directory: "crates/gnunet-cadet",
        core: true,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-session-crypto",
            "gnunet-types",
            "gnunet-wire",
            "subtle",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-fs",
        directory: "apps/gnunet-service-fs",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-cadet-host",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-core-client-host",
            "gnunet-datastore-host",
            "gnunet-dht-client-host",
            "gnunet-fs",
            "gnunet-fs-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-datastore",
        directory: "apps/gnunet-service-datastore",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-config",
            "gnunet-datastore",
            "gnunet-datastore-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-datastore",
        directory: "crates/gnunet-datastore",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-fs-host",
        directory: "adapters/fs-std",
        core: false,
        dependencies: &[
            "time",
            "unicode-normalization",
            "gnunet-core-client-host",
            "gnunet-dht-client-host",
            "gnunet-cadet-host",
            "gnunet-config",
            "gnunet-datastore",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-fs",
            "gnunet-fs-codec",
            "gnunet-extractor-host",
            "gnunet-types",
            "gnunet-crypto",
            "nix",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-wire",
            "tokio",
            "gnunet-datastore-host",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-datastore-host",
        directory: "adapters/datastore-std",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-datastore",
            "gnunet-crypto",
            "getrandom",
            "nix",
            "uzers",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-fs-codec",
        directory: "crates/gnunet-fs-codec",
        core: true,
        dependencies: &["gnunet-fs", "miniz_oxide"],
    },
    Policy {
        name: "gnunet-fs",
        directory: "crates/gnunet-fs",
        core: true,
        dependencies: &[
            "gnunet-block",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "subtle",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-dht",
        directory: "crates/gnunet-dht",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-block",
            "gnunet-hello",
        ],
    },
    Policy {
        name: "gnunet-dht-client",
        directory: "crates/gnunet-dht-client",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-hello",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-dns2gns-host",
        directory: "adapters/dns2gns-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-dns",
            "gnunet-dnsstub-host",
            "gnunet-gns-host",
            "gnunet-gns-client-host",
            "gnunet-identity-client-host",
            "gnunet-vpn-client-host",
            "gnunet-vpn",
            "gnunet-gnsrecord",
            "gnunet-idna",
            "gnunet-service-runtime",
            "gnunet-types",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-nss-host",
        directory: "adapters/gns-nss-std",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-config",
            "gnunet-client-host",
            "gnunet-gns-host",
            "gnunet-gns-client-host",
            "gnunet-identity-client-host",
            "gnunet-resolver-broker",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-dns",
            "gnunet-idna",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-proxy-host",
        directory: "adapters/gns-proxy-std",
        core: false,
        dependencies: &[
            "gnunet-types",
            "gnunet-config",
            "gnunet-client-host",
            "gnunet-gns-host",
            "gnunet-gns-client-host",
            "gnunet-identity-client-host",
            "gnunet-gnsrecord",
            "gnunet-idna",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-native",
            "gnunet-vpn-client-host",
            "gnunet-vpn",
            "socket2",
            "tokio",
            "hyper",
            "hyper-util",
            "tokio-rustls",
            "rustls",
            "rcgen",
            "rustls-webpki",
            "x509-parser",
            "aws-lc-rs",
            "webpki-roots",
            "time",
            "yasna",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-gns-proxy-command",
        directory: "apps/gnunet-gns-proxy",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-gns-proxy-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-native",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-proxy-setup-ca-command",
        directory: "apps/gnunet-gns-proxy-setup-ca",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-config",
            "gnunet-types",
            "rcgen",
            "base64ct",
            "time",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-dht-service-host",
        directory: "adapters/dht-std",
        core: false,
        dependencies: &[
            "gnunet-block",
            "gnunet-client-host",
            "gnunet-core-client-host",
            "gnunet-crypto",
            "gnunet-dht",
            "gnunet-hello",
            "gnunet-native",
            "gnunet-nse-client-host",
            "gnunet-peerstore-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-transport-application-host",
            "gnunet-types",
            "gnunet-wire",
            "libc",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-communicator-udp",
        directory: "apps/gnunet-communicator-udp",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-native",
            "gnunet-nat-client-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-transport-application-host",
            "gnunet-types",
            "gnunet-udp-communicator-core",
            "gnunet-udp-communicator-host",
            "gnunet-wire",
            "getrandom",
            "nix",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-gns",
        directory: "apps/gnunet-service-gns",
        core: false,
        dependencies: &[
            "gnunet-gns-service-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-native",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-dht",
        directory: "apps/gnunet-service-dht",
        core: false,
        dependencies: &[
            "gnunet-block",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-dht-service-host",
            "gnunet-pils",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "tokio",
            "getrandom",
        ],
    },
    Policy {
        name: "gnunet-dht-command",
        directory: "apps/gnunet-dht",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-dht-client-host",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-dns2gns-command",
        directory: "apps/gnunet-dns2gns",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-dns2gns-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-service-host",
        directory: "adapters/gns-service-std",
        core: false,
        dependencies: &[
            "gnunet-gns",
            "gnunet-types",
            "tokio",
            "gnunet-block",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-dht-client-host",
            "gnunet-dns-client-host",
            "gnunet-idna",
            "gnunet-namecache-client-host",
            "gnunet-revocation-client-host",
            "gnunet-service-runtime",
            "gnunet-wire",
            "gnunet-dns",
            "gnunet-resolver-broker",
            "getrandom",
            "aws-lc-rs",
            "gnunet-client",
            "gnunet-gnsrecord",
            "gnunet-native",
        ],
    },
    Policy {
        name: "gnunet-gns-host",
        directory: "adapters/gns-api-std",
        core: false,
        dependencies: &[
            "gnunet-gns-client-host",
            "gnunet-identity-client-host",
            "gnunet-config",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-command",
        directory: "apps/gnunet-gns",
        core: false,
        dependencies: &[
            "gnunet-program-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-gns-client-host",
            "gnunet-gns-host",
            "gnunet-identity-client-host",
            "gnunet-gnsrecord-text",
            "gnunet-dns",
            "gnunet-idna",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "zeroize",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-gns-client-host",
        directory: "adapters/gns-client-std",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-gnsrecord",
            "gnunet-types",
            "gnunet-config",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-dht-client-host",
        directory: "adapters/dht-client-std",
        core: false,
        dependencies: &[
            "gnunet-dht-client",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-hello",
            "gnunet-config",
            "gnunet-crypto",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nse-host",
        directory: "adapters/nse-std",
        core: false,
        dependencies: &[
            "gnunet-nse",
            "gnunet-crypto",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-core-client-host",
            "gnunet-client-host",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "getrandom",
            "tokio",
            "gnunet-client",
            "gnunet-program-host",
        ],
    },
    Policy {
        name: "gnunet-service-nse",
        directory: "apps/gnunet-service-nse",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-nse-host",
            "gnunet-ipc-unix",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-nse",
        directory: "crates/gnunet-nse",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-crypto", "libm"],
    },
    Policy {
        name: "gnunet-client-host",
        directory: "adapters/client-std",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-types",
            "gnunet-service-runtime",
            "nix",
            "socket2",
            "tokio",
            "gnunet-resolver-broker",
        ],
    },
    Policy {
        name: "gnunet-core-client-host",
        directory: "adapters/core-client-std",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-core-host",
        directory: "adapters/core-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-core",
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-core",
        directory: "apps/gnunet-service-core",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-core-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-transport",
        directory: "crates/gnunet-transport",
        core: true,
        dependencies: &[
            "gnunet-nat",
            "zeroize",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-client",
            "gnunet-hello",
        ],
    },
    Policy {
        name: "gnunet-tcp-replay-host",
        directory: "adapters/tcp-replay-std",
        core: false,
        dependencies: &[
            "gnunet-snapshot-host",
            "gnunet-tcp-communicator-core",
            "gnunet-crypto",
            "gnunet-types",
            "getrandom",
            "libc",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-tcp-communicator-runtime",
        directory: "adapters/tcp-runtime-std",
        core: false,
        dependencies: &[
            "gnunet-tcp-replay-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-client-host",
            "gnunet-native",
            "gnunet-nat-client-host",
            "gnunet-resolver-broker",
            "gnunet-config",
            "gnunet-tcp-communicator-core",
            "gnunet-tcp-communicator-host",
            "gnunet-service-runtime",
            "gnunet-crypto",
            "gnunet-types",
            "socket2",
            "libc",
            "getrandom",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-communicator-tcp",
        directory: "apps/gnunet-communicator-tcp",
        core: false,
        dependencies: &[
            "gnunet-ipc-unix",
            "gnunet-tcp-communicator-runtime",
            "gnunet-service-startup",
            "gnunet-program-host",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-pils-host",
            "gnunet-nat-client-host",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-transport-runtime",
        directory: "adapters/transport-runtime-std",
        core: false,
        dependencies: &[
            "gnunet-transport",
            "gnunet-transport-host",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-crypto",
            "getrandom",
            "tokio",
            "gnunet-wire",
            "gnunet-hello",
        ],
    },
    Policy {
        name: "gnunet-transport-node",
        directory: "apps/gnunet-transport-node",
        core: false,
        dependencies: &[
            "gnunet-transport-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-transport-host",
        directory: "adapters/transport-std",
        core: false,
        dependencies: &[
            // Native journal opens use O_DIRECTORY/O_NOFOLLOW constants.
            "libc",
            "socket2",
            "getrandom",
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-service-runtime",
            "gnunet-session-crypto",
            "gnunet-tcp-communicator-core",
            "gnunet-tcp-communicator-host",
            "gnunet-transport",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-pils",
        directory: "crates/gnunet-pils",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "gnunet-hello",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-pils-host",
        directory: "adapters/pils-std",
        core: false,
        dependencies: &[
            "gnunet-pils",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "serde_json",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-hello",
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "libc",
            "nix",
            "tokio",
            "getrandom",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-core",
        directory: "crates/gnunet-core",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "zeroize",
            "subtle",
        ],
    },
    Policy {
        name: "gnunet-types",
        directory: "crates/gnunet-types",
        core: true,
        dependencies: &[],
    },
    Policy {
        name: "gnunet-resources",
        directory: "crates/gnunet-resources",
        core: true,
        dependencies: &["gnunet-types"],
    },
    Policy {
        name: "gnunet-wire",
        directory: "crates/gnunet-wire",
        core: true,
        dependencies: &["gnunet-types", "gnunet-gnsrecord"],
    },
    Policy {
        name: "gnunet-crypto",
        directory: "crates/gnunet-crypto",
        core: true,
        dependencies: &[
            "argon2",
            "gnunet-types",
            "gnunet-wire",
            "ed25519-dalek",
            "sha2",
            "zeroize",
            "curve25519-dalek",
            "crypto-bigint",
            "aes",
            "ctr",
            "salsa20",
            "poly1305",
            "subtle",
        ],
    },
    Policy {
        name: "gnunet-client",
        directory: "crates/gnunet-client",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-gnsrecord"],
    },
    Policy {
        name: "gnunet-gns",
        directory: "crates/gnunet-gns",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "gnunet-gnscrypto",
            "gnunet-dns",
            "gnunet-idna",
        ],
    },
    Policy {
        name: "gnunet-gnsrecord",
        directory: "crates/gnunet-gnsrecord",
        core: true,
        dependencies: &["gnunet-types"],
    },
    Policy {
        name: "gnunet-gnscrypto",
        directory: "crates/gnunet-gnscrypto",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-gnsrecord",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-statistics",
        directory: "crates/gnunet-statistics",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-client"],
    },
    Policy {
        name: "gnunet-block",
        directory: "crates/gnunet-block",
        core: true,
        dependencies: &["gnunet-types", "gnunet-crypto", "gnunet-hello"],
    },
    Policy {
        name: "gnunet-hello",
        directory: "crates/gnunet-hello",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire", "gnunet-crypto"],
    },
    Policy {
        name: "gnunet-dns",
        directory: "crates/gnunet-dns",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-session-crypto",
        directory: "crates/gnunet-session-crypto",
        core: true,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-types",
            "curve25519-dalek",
            "crypto-bigint",
            "sha2",
            "zeroize",
            "subtle",
            "chacha20",
            "cipher",
            "aes",
            "ctr",
            "poly1305",
            "ghash",
            "polyval",
        ],
    },
    Policy {
        name: "gnunet-transport-application-host",
        directory: "adapters/transport-application-std",
        core: false,
        dependencies: &[
            "gnunet-client-host",
            "gnunet-service-runtime",
            "gnunet-transport",
            "gnunet-hello",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-udp-communicator-host",
        directory: "adapters/udp-communicator-std",
        core: false,
        dependencies: &[
            "gnunet-udp-communicator-core",
            "gnunet-crypto",
            "gnunet-types",
            "getrandom",
            "zeroize",
            "socket2",
            "tokio",
            "gnunet-pils",
            "gnunet-pils-host",
            "gnunet-wire",
            "gnunet-transport",
            "gnunet-service-runtime",
            "gnunet-nat-burst-host",
            "gnunet-transport-host",
            "gnunet-native",
            "libc",
        ],
    },
    Policy {
        name: "gnunet-udp-communicator-core",
        directory: "crates/gnunet-udp-communicator-core",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "zeroize",
            "getrandom",
            "serde_json",
        ],
    },
    Policy {
        name: "gnunet-tcp-communicator-core",
        directory: "crates/gnunet-tcp-communicator-core",
        core: true,
        dependencies: &[
            "gnunet-types",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-session-crypto",
            "zeroize",
            "subtle",
        ],
    },
    Policy {
        name: "gnunet-tcp-communicator-host",
        directory: "adapters/tcp-communicator-std",
        core: false,
        dependencies: &[
            "gnunet-crypto",
            "gnunet-hello",
            "gnunet-service-runtime",
            "gnunet-session-crypto",
            "gnunet-tcp-communicator-core",
            "gnunet-types",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-arm-service-core",
        directory: "crates/gnunet-arm-service-core",
        core: true,
        dependencies: &["gnunet-arm-core", "gnunet-types"],
    },
    Policy {
        name: "gnunet-arm-core",
        directory: "crates/gnunet-arm-core",
        core: true,
        dependencies: &["gnunet-types", "gnunet-wire"],
    },
    Policy {
        name: "gnunet-resolver-service-core",
        directory: "crates/gnunet-resolver-service-core",
        core: true,
        dependencies: &[
            "gnunet-client",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-dns",
            "gnunet-dnsstub",
        ],
    },
    Policy {
        name: "gnunet-idna",
        directory: "crates/gnunet-idna",
        core: true,
        dependencies: &["gnunet-dns"],
    },
    Policy {
        name: "gnunet-dnsstub",
        directory: "crates/gnunet-dnsstub",
        core: true,
        dependencies: &["gnunet-types"],
    },
    Policy {
        name: "gnunet-dnsstub-host",
        directory: "adapters/dns-std",
        core: false,
        dependencies: &[
            "gnunet-dnsstub",
            "gnunet-types",
            "tokio",
            "socket2",
            "getrandom",
        ],
    },
    Policy {
        name: "gnunet-resolver-broker",
        directory: "adapters/resolver-broker-std",
        core: false,
        dependencies: &[
            "gnunet-arm-core",
            "gnunet-arm-host",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-native",
            "gnunet-service-runtime",
            "gnunet-types",
            "gnunet-wire",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-arm-host",
        directory: "adapters/arm-std",
        core: false,
        dependencies: &[
            "gnunet-arm-core",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "libc",
            "nix",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-arm-service-host",
        directory: "adapters/arm-service-std",
        core: false,
        dependencies: &[
            "gnunet-arm-core",
            "gnunet-arm-service-core",
            "gnunet-config",
            "gnunet-native",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "libc",
            "nix",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-resolver-host",
        directory: "adapters/resolver-std",
        core: false,
        dependencies: &[
            "getrandom",
            "gnunet-client",
            "gnunet-config",
            "gnunet-dns",
            "gnunet-dnsstub-host",
            "gnunet-idna",
            "gnunet-resolver-service-core",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "gnunet-wire",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-arm-cli",
        directory: "apps/gnunet-arm",
        core: false,
        dependencies: &[
            "gnunet-resolver-broker",
            "gnunet-arm-host",
            "gnunet-arm-core",
            "gnunet-config",
            "gnunet-client-host",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-types",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-resolver",
        directory: "apps/gnunet-service-resolver",
        core: false,
        dependencies: &[
            "gnunet-config",
            "gnunet-program-host",
            "gnunet-resolver-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-config",
        directory: "adapters/config-std",
        core: false,
        dependencies: &["uzers", "nix", "gnunet-native"],
    },
    Policy {
        name: "gnunet-program-host",
        directory: "adapters/program-std",
        core: false,
        dependencies: &[
            "libc",
            "getrandom",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-types",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-native",
        directory: "adapters/native-std",
        core: false,
        dependencies: &["libc", "windows-sys"],
    },
    Policy {
        name: "gnunet-statistics-store",
        directory: "adapters/statistics-store",
        core: false,
        dependencies: &[
            "gnunet-statistics",
            "gnunet-types",
            "gnunet-wire",
            "gnunet-client",
        ],
    },
    Policy {
        name: "gnunet-service-startup",
        directory: "adapters/service-startup",
        core: false,
        dependencies: &[
            "gnunet-service-runtime",
            "gnunet-config",
            "nix",
            "uzers",
            "libc",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-service-runtime",
        directory: "adapters/service-runtime",
        core: false,
        dependencies: &[
            "uzers",
            "gnunet-wire",
            "zeroize",
            "gnunet-config",
            "gnunet-crypto",
            "gnunet-native",
            "gnunet-types",
            "libc",
            "nix",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet",
        directory: "crates/gnunet",
        core: true,
        dependencies: &[
            "gnunet-secretsharing-host",
            "gnunet-uri-host",
            "gnunet-qr-host",
            "gnunet-secretsharing-keygen-host",
            "gnunet-conversation-host",
            "gnunet-conversation-audio-host",
            "gnunet-conversation-client-host",
            "gnunet-secretsharing-decrypt-host",
            "gnunet-conversation",
            "gnunet-secretsharing-client-host",
            "gnunet-abd-host",
            "gnunet-secretsharing",
            "gnunet-consensus-host",
            "gnunet-abd",
            "gnunet-abd-client-host",
            "gnunet-consensus-client-host",
            "gnunet-consensus",
            "gnunet-scalarproduct-paillier",
            "gnunet-scalarproduct-host",
            "gnunet-paillier",
            "gnunet-scalarproduct",
            "gnunet-set",
            "gnunet-set-host",
            "gnunet-scalarproduct-client-host",
            "gnunet-set-client-host",
            "gnunet-rps",
            "gnunet-rps-host",
            "gnunet-rps-client-host",
            "gnunet-quic-communicator-host",
            "gnunet-transport-quic",
            "gnunet-transport-dv-bridge-host",
            "gnunet-transport-dv-runtime-host",
            "gnunet-transport-dv-store-host",
            "gnunet-transport-service-host",
            "gnunet-transport-dv-crypto",
            "gnunet-transport-dv-crypto-host",
            "gnunet-unix-communicator",
            "gnunet-unix-communicator-host",
            "gnunet-nse-client-host",
            "gnunet-zonemaster",
            "gnunet-zonemaster-host",
            "gnunet-dns-tools-host",
            "gnunet-dns-interception",
            "gnunet-dns-service-host",
            "gnunet-hostlist",
            "gnunet-hostlist-host",
            "gnunet-pt-host",
            "gnunet-testbed",
            "gnunet-testbed-host",
            "gnunet-pt",
            "gnunet-dns-client-host",
            "gnunet-nat-test-host",
            "gnunet-nat-burst-host",
            "gnunet-nat-client-host",
            "gnunet-namestore",
            "gnunet-namestore-host",
            "gnunet-reclaim",
            "gnunet-reclaim-credentials",
            "gnunet-rest",
            "gnunet-gnsrecord-text",
            "gnunet-zoneimport-core",
            "gnunet-zoneimport-host",
            "gnunet-json",
            "gnunet-reclaim-client-host",
            "gnunet-reclaim-host",
            "gnunet-rest-host",
            "gnunet-oidc-crypto-host",
            "gnunet-messenger-host",
            "gnunet-messenger-service-host",
            "gnunet-messenger-client-host",
            "gnunet-messenger",
            "gnunet-messenger-core",
            "gnunet-revocation-client-host",
            "gnunet-revocation-host",
            "gnunet-nat",
            "gnunet-topology",
            "gnunet-topology-host",
            "gnunet-nat-host",
            "gnunet-revocation",
            "gnunet-did",
            "gnunet-did-host",
            "gnunet-namestore-client-host",
            "gnunet-datacache",
            "gnunet-namecache-host",
            "gnunet-namecache",
            "gnunet-namecache-client-host",
            "gnunet-identity",
            "gnunet-identity-client-host",
            "gnunet-identity-host",
            "gnunet-regex",
            "gnunet-regex-service",
            "gnunet-regex-server-host",
            "gnunet-regex-program-host",
            "gnunet-regex-client-host",
            "gnunet-vpn-host",
            "gnunet-exit-host",
            "gnunet-vpn",
            "gnunet-exit",
            "gnunet-tun-host",
            "gnunet-vpn-client-host",
            "gnunet-seti-host",
            "gnunet-setu-host",
            "gnunet-seti",
            "gnunet-setu",
            "gnunet-setu-client-host",
            "gnunet-seti-client-host",
            "gnunet-peerstore",
            "gnunet-peerstore-host",
            "gnunet-peerstore-client-host",
            "gnunet-cadet",
            "gnunet-cadet-host",
            "gnunet-fs-codec",
            "gnunet-fs",
            "gnunet-fs-host",
            "gnunet-datastore-host",
            "gnunet-datastore",
            "gnunet-gns-client-host",
            "gnunet-nse-host",
            "gnunet-core-client-host",
            "gnunet-dht-client-host",
            "gnunet-nse",
            "gnunet-client-host",
            "gnunet-core-host",
            "gnunet-transport",
            "gnunet-transport-host",
            "gnunet-transport-application-host",
            "gnunet-program-host",
            "gnunet-pils-host",
            "gnunet-block",
            "gnunet-resolver-broker",
            "gnunet-types",
            "gnunet-resources",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-client",
            "gnunet-core",
            "gnunet-pils",
            "gnunet-gnsrecord",
            "gnunet-gnscrypto",
            "gnunet-gns",
            "gnunet-hello",
            "gnunet-dns",
            "gnunet-idna",
            "gnunet-resolver-service-core",
            "gnunet-arm-core",
            "gnunet-arm-service-core",
            "gnunet-session-crypto",
            "gnunet-tcp-communicator-core",
            "gnunet-udp-communicator-core",
            "gnunet-tcp-communicator-host",
            "gnunet-dnsstub",
            "gnunet-statistics",
            "gnunet-ipc-unix",
            "gnunet-config",
            "gnunet-dnsstub-host",
            "gnunet-statistics-store",
            "gnunet-resolver-host",
            "gnunet-arm-host",
            "gnunet-arm-service-host",
            "gnunet-service-startup",
            "gnunet-service-runtime",
        ],
    },
    Policy {
        name: "gnunet-ipc-unix",
        directory: "adapters/ipc-unix",
        core: false,
        dependencies: &[
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-native",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-statistics",
            "gnunet-types",
            "gnunet-wire",
            "nix",
            "socket2",
            "tokio",
        ],
    },
    Policy {
        name: "gnunet-cli",
        directory: "apps/gnunet-cli",
        core: false,
        dependencies: &[
            "gnunet",
            "gnunet-client",
            "gnunet-client-host",
            "gnunet-config",
            "gnunet-ipc-unix",
            "gnunet-program-host",
            "gnunet-resolver-broker",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "gnunet-types",
            "nix",
            "serde_json",
            "tokio",
            "zeroize",
        ],
    },
    Policy {
        name: "gnunet-service-statistics",
        directory: "apps/gnunet-service-statistics",
        core: false,
        dependencies: &[
            "gnunet",
            "gnunet-program-host",
            "gnunet-service-runtime",
            "gnunet-service-startup",
            "tokio",
            "libc",
            "nix",
        ],
    },
    Policy {
        name: "xtask",
        directory: "tools/xtask",
        core: false,
        dependencies: &["gnunet-crypto", "serde_json"],
    },
];

pub(crate) const EMBEDDED_TARGETS: &[&str] = &["thumbv6m-none-eabi", "thumbv7em-none-eabi"];

/// Reuse the architecture inventory so new core packages enter portable CI.
/// The facade's host features are tested with the native workspace instead.
pub(crate) fn portable_packages() -> impl Iterator<Item = &'static str> {
    POLICIES
        .iter()
        .filter(|rule| rule.core && rule.name != "gnunet")
        .map(|rule| rule.name)
}

fn field<'a>(value: &'a Value, key: &str) -> CheckResult<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}").into())
}
fn array<'a>(value: &'a Value, key: &str) -> CheckResult<&'a Vec<Value>> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("missing array {key}").into())
}
fn policy(name: &str) -> CheckResult<&'static Policy> {
    POLICIES
        .iter()
        .find(|rule| rule.name == name)
        .ok_or_else(|| format!("package has no official architecture policy: {name}").into())
}
fn metadata_args(args: &[&str]) -> CheckResult<Value> {
    let output = Command::new("cargo").args(args).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn metadata() -> CheckResult<Value> {
    metadata_args(&["metadata", "--format-version", "1", "--no-deps", "--locked"])
}
fn members(meta: &Value) -> CheckResult<Vec<&Value>> {
    let ids = array(meta, "workspace_members")?;
    Ok(array(meta, "packages")?
        .iter()
        .filter(|package| ids.contains(&package["id"]))
        .collect())
}
fn forbidden_feature(feature: &str) -> bool {
    feature == "no_std"
        || feature
            .split(['-', '_', '/', ':', '?'])
            .any(|part| matches!(part, "legacy" | "native" | "full"))
}
fn c_gnunet(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace('_', "-");
    name.contains("libgnunet") || (name.contains("gnunet") && name.ends_with("-sys"))
}

pub(crate) fn check_deps() -> CheckResult<()> {
    validate_dependencies(&metadata()?)
}

fn validate_dependencies(meta: &Value) -> CheckResult<()> {
    let root = Path::new(field(meta, "workspace_root")?);
    let mut seen = BTreeSet::new();
    for package in members(meta)? {
        let name = field(package, "name")?;
        let rule = policy(name)?;
        if !seen.insert(name) {
            return Err(format!("duplicate package: {name}").into());
        }
        if Path::new(field(package, "manifest_path")?)
            != root.join(rule.directory).join("Cargo.toml")
        {
            return Err(format!("package is outside its architecture directory: {name}").into());
        }
        if package["links"].as_str().is_some_and(c_gnunet) {
            return Err("production libgnunet FFI is forbidden".into());
        }
        for dependency in array(package, "dependencies")? {
            // Cargo exposes the package name independently of local renames and
            // target/optional/build flags. None can bypass this boundary.
            let dependency_name = field(dependency, "name")?;
            if c_gnunet(dependency_name) || !rule.dependencies.contains(&dependency_name) {
                return Err(format!("forbidden dependency {name} -> {dependency_name}").into());
            }
            for requested in array(dependency, "features")? {
                let feature = requested
                    .as_str()
                    .ok_or("dependency feature is not a string")?;
                if forbidden_feature(feature) {
                    return Err(
                        format!("removed private feature requested: {name}/{feature}").into(),
                    );
                }
            }
            if rule.core
                && POLICIES
                    .iter()
                    .any(|candidate| candidate.name == dependency_name && !candidate.core)
                && dependency["optional"] != true
            {
                return Err(
                    "host adapters must remain optional dependencies of the no_std core".into(),
                );
            }
        }
    }
    for required in POLICIES {
        if !seen.contains(required.name) {
            return Err(format!("required workspace package absent: {}", required.name).into());
        }
    }
    validate_generic_runtime_boundary(meta)?;
    validate_shared_io_boundaries(meta)
}

/// Check the workspace production closure across optional/target configurations.
/// Domain adapters may exercise the runtime in tests without becoming runtime
/// dependencies; Cargo's package name, not its local rename, identifies an edge.
/// External dependency internals remain outside this metadata --no-deps check.
fn validate_generic_runtime_boundary(meta: &Value) -> CheckResult<()> {
    const GENERIC_PACKAGES: &[&str] = &[
        "gnunet-service-runtime",
        "gnunet-config",
        "gnunet-native",
        "gnunet-types",
        "gnunet-wire",
        // Fixed record/key codecs depend only on types, without a service owner.
        "gnunet-gnsrecord",
        "gnunet-crypto",
        "gnunet-resources",
    ];
    let packages: BTreeMap<_, _> = members(meta)?
        .into_iter()
        .map(|package| Ok((field(package, "name")?, package)))
        .collect::<CheckResult<_>>()?;
    let root = "gnunet-service-runtime";
    if !packages.contains_key(root) {
        return Err("generic service runtime package absent".into());
    }
    let mut pending = vec![(root, vec![root])];
    let mut visited = BTreeSet::new();
    while let Some((name, path)) = pending.pop() {
        if !visited.insert(name) {
            continue;
        }
        let package = packages
            .get(name)
            .ok_or("runtime dependency package absent")?;
        for dependency in array(package, "dependencies")? {
            // Inspect all declared normal dependencies, including optional and
            // platform-specific ones. Dev/build edges are not runtime linkage.
            if !dependency["kind"].is_null() {
                continue;
            }
            let dependency_name = field(dependency, "name")?;
            if !packages.contains_key(dependency_name) {
                continue;
            }
            let mut dependency_path = path.clone();
            dependency_path.push(dependency_name);
            if !GENERIC_PACKAGES.contains(&dependency_name) {
                return Err(format!(
                    "generic runtime reaches domain package: {}",
                    dependency_path.join(" -> ")
                )
                .into());
            }
            pending.push((dependency_name, dependency_path));
        }
    }
    Ok(())
}

/// The shared CLIENT adapter inverts Resolver effects and cannot import a broker.
/// Protocol hosts must not reacquire Statistics through any normal intermediate.
fn validate_shared_io_boundaries(meta: &Value) -> CheckResult<()> {
    let packages: BTreeMap<_, _> = members(meta)?
        .into_iter()
        .map(|p| Ok((field(p, "name")?, p)))
        .collect::<CheckResult<_>>()?;
    for root in [
        "gnunet-secretsharing-host",
        "gnunet-secretsharing-keygen-host",
        "gnunet-conversation-host",
        "gnunet-conversation-client-host",
        "gnunet-secretsharing-decrypt-host",
        "gnunet-secretsharing-client-host",
        "gnunet-abd-host",
        "gnunet-consensus-host",
        "gnunet-abd-client-host",
        "gnunet-consensus-client-host",
        "gnunet-scalarproduct-host",
        "gnunet-set-host",
        "gnunet-scalarproduct-client-host",
        "gnunet-set-client-host",
        "gnunet-rps-host",
        "gnunet-rps-client-host",
        "gnunet-regex-server-host",
        "gnunet-quic-communicator-host",
        "gnunet-transport-dv-bridge-host",
        "gnunet-transport-dv-runtime-host",
        "gnunet-transport-dv-store-host",
        "gnunet-transport-dv-crypto-host",
        "gnunet-unix-communicator-host",
        "gnunet-tcp-communicator-runtime",
        "gnunet-transport-runtime",
        "gnunet-nse-host",
        "gnunet-core-client-host",
        "gnunet-dht-client-host",
        "gnunet-gns-client-host",
        "gnunet-core-host",
        "gnunet-transport-host",
        "gnunet-tcp-communicator-host",
        "gnunet-udp-communicator-host",
        "gnunet-resolver-broker",
        "gnunet-resolver-host",
        "gnunet-arm-host",
        "gnunet-arm-service-host",
        "gnunet-client-host",
    ] {
        if !packages.contains_key(root) {
            return Err(format!("shared I/O boundary package absent: {root}").into());
        }
        let mut pending = vec![(root, vec![root])];
        let mut visited = BTreeSet::new();
        while let Some((name, path)) = pending.pop() {
            if !visited.insert(name) {
                continue;
            }
            for dependency in array(
                packages.get(name).ok_or("boundary dependency absent")?,
                "dependencies",
            )? {
                if !dependency["kind"].is_null() {
                    continue;
                }
                let target = field(dependency, "name")?;
                if !packages.contains_key(target) {
                    continue;
                }
                let mut next = path.clone();
                next.push(target);
                if ["gnunet-ipc-unix", "gnunet-statistics"].contains(&target)
                    || (root == "gnunet-udp-communicator-host" && target == "gnunet-transport-host")
                    || (root == "gnunet-tcp-communicator-runtime"
                        && [
                            "gnunet-transport-host",
                            "gnunet-core-host",
                            "gnunet-core-client-host",
                            "gnunet-nse-host",
                            "gnunet-dht-client-host",
                            "gnunet-gns-client-host",
                            "gnunet-udp-communicator-host",
                        ]
                        .contains(&target))
                    || (root == "gnunet-transport-runtime"
                        && [
                            "gnunet-core-host",
                            "gnunet-core-client-host",
                            "gnunet-nse-host",
                            "gnunet-dht-client-host",
                            "gnunet-tcp-communicator-host",
                            "gnunet-udp-communicator-host",
                        ]
                        .contains(&target))
                    || (root == "gnunet-nse-host"
                        && [
                            "gnunet-core-host",
                            "gnunet-transport-host",
                            "gnunet-tcp-communicator-host",
                        ]
                        .contains(&target))
                    || (root == "gnunet-gns-client-host"
                        && ![
                            "gnunet-gns-client-host",
                            "gnunet-client",
                            "gnunet-client-host",
                            "gnunet-service-runtime",
                            "gnunet-gnsrecord",
                            "gnunet-config",
                            "gnunet-native",
                            "gnunet-types",
                            "gnunet-wire",
                            "gnunet-crypto",
                            "gnunet-resources",
                        ]
                        .contains(&target))
                    || (root == "gnunet-client-host"
                        && ![
                            "gnunet-client-host",
                            "gnunet-service-runtime",
                            "gnunet-config",
                            "gnunet-types",
                            "gnunet-native",
                            "gnunet-wire",
                            "gnunet-gnsrecord",
                            "gnunet-crypto",
                            "gnunet-resources",
                        ]
                        .contains(&target))
                {
                    return Err(format!(
                        "shared I/O production boundary violated: {}",
                        next.join(" -> ")
                    )
                    .into());
                }
                pending.push((target, next));
            }
        }
    }
    Ok(())
}

pub(crate) fn check_features() -> CheckResult<()> {
    let meta = metadata()?;
    validate_features(&meta)?;
    validate_pils_feature_boundary(&meta)?;
    validate_dht_client_feature_boundary(&meta)?;
    validate_metadata_codec_boundary(&meta)?;
    validate_gns_client_feature_boundary(&meta)?;
    validate_isolated_client_feature(
        &meta,
        "official-transport-observation",
        "gnunet-transport-application-host",
    )?;
    validate_isolated_client_feature(&meta, "official-nse-client", "gnunet-nse-client-host")?;
    validate_isolated_client_feature(&meta, "official-rps-client", "gnunet-rps-client-host")?;
    validate_isolated_client_feature(&meta, "official-abd-client", "gnunet-abd-client-host")?;
    validate_isolated_client_feature(
        &meta,
        "official-conversation-client",
        "gnunet-conversation-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-secretsharing-client",
        "gnunet-secretsharing-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-consensus-client",
        "gnunet-consensus-client-host",
    )?;
    validate_isolated_client_feature(&meta, "official-vpn-client", "gnunet-vpn-client-host")?;
    validate_isolated_client_feature(&meta, "official-nat-client", "gnunet-nat-client-host")?;
    validate_isolated_client_feature(&meta, "official-nat-burst", "gnunet-nat-burst-host")?;
    validate_isolated_client_feature(&meta, "official-nat-test", "gnunet-nat-test-host")?;
    validate_isolated_client_feature(&meta, "official-dns-client", "gnunet-dns-client-host")?;
    validate_isolated_client_feature(&meta, "official-testbed", "gnunet-testbed-host")?;
    validate_isolated_client_feature(&meta, "official-did-client", "gnunet-did-host")?;
    validate_isolated_client_feature(
        &meta,
        "official-messenger-client",
        "gnunet-messenger-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-reclaim-client",
        "gnunet-reclaim-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-namestore-client",
        "gnunet-namestore-client-host",
    )?;
    validate_isolated_client_feature(&meta, "official-regex-client", "gnunet-regex-client-host")?;
    validate_isolated_client_feature(
        &meta,
        "official-namecache-client",
        "gnunet-namecache-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-identity-client",
        "gnunet-identity-client-host",
    )?;
    validate_isolated_client_feature(
        &meta,
        "official-scalarproduct-client",
        "gnunet-scalarproduct-client-host",
    )?;
    validate_isolated_client_feature(&meta, "official-set-client", "gnunet-set-client-host")?;
    validate_isolated_client_feature(&meta, "official-setu-client", "gnunet-setu-client-host")?;
    validate_isolated_client_feature(&meta, "official-seti-client", "gnunet-seti-client-host")?;
    validate_isolated_client_feature(
        &meta,
        "official-peerstore-client",
        "gnunet-peerstore-client-host",
    )?;
    check_fs_extraction_graphs()
}

/// Resolve each independent offline SDK entry point. Manifest feature spelling
/// alone cannot prove that an intermediate normal dependency stays offline.
fn check_fs_extraction_graphs() -> CheckResult<()> {
    for feature in ["host", "facade"] {
        let meta = metadata_args(&[
            "metadata",
            "--manifest-path",
            "tests/features/fs-extraction/Cargo.toml",
            "--format-version",
            "1",
            "--no-default-features",
            "--features",
            feature,
            "--locked",
            "--offline",
        ])?;
        validate_fs_extraction_graph(&meta, feature)?;
    }
    Ok(())
}

fn validate_fs_extraction_graph(meta: &Value, feature: &str) -> CheckResult<()> {
    let packages: BTreeMap<_, _> = array(meta, "packages")?
        .iter()
        .map(|package| Ok((field(package, "id")?, package)))
        .collect::<CheckResult<_>>()?;
    let nodes: BTreeMap<_, _> = array(&meta["resolve"], "nodes")?
        .iter()
        .map(|node| Ok((field(node, "id")?, node)))
        .collect::<CheckResult<_>>()?;
    let root = field(&meta["resolve"], "root")?;
    let root_package = packages.get(root).ok_or("offline FS fixture root absent")?;
    let root_node = nodes.get(root).ok_or("offline FS fixture node absent")?;
    let root_features = array(root_node, "features")?;
    if !matches!(feature, "host" | "facade")
        || field(root_package, "name")? != "gnunet-fs-extraction-check"
        || root_features.len() != 1
        || root_features.first().and_then(Value::as_str) != Some(feature)
    {
        return Err("offline FS fixture must select exactly one SDK entry point".into());
    }
    let mut pending = vec![(root, Vec::new())];
    let mut visited = BTreeSet::new();
    let mut seen = BTreeSet::new();
    while let Some((id, mut path)) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages
            .get(id)
            .ok_or("offline FS resolved package absent")?;
        let node = nodes.get(id).ok_or("offline FS resolved node absent")?;
        let name = field(package, "name")?;
        let manifest = field(package, "manifest_path")?;
        path.push(name);
        let permitted_host = matches!(name, "gnunet-fs-host" | "gnunet-extractor-host");
        if (manifest.contains("/adapters/") && !permitted_host)
            || manifest.contains("/apps/")
            || c_gnunet(name)
            || matches!(
                name,
                "tokio"
                    | "async-io"
                    | "mio"
                    | "socket2"
                    | "gnunet-service-runtime"
                    | "gnunet-client-host"
                    | "gnunet-datastore-host"
            )
        {
            return Err(format!(
                "offline FS extraction production boundary violated: {}",
                path.join(" -> ")
            )
            .into());
        }
        if name == "gnunet-fs-host" {
            let features = array(node, "features")?;
            if !features.iter().any(|value| value == "extraction")
                || features.iter().any(|value| {
                    matches!(
                        value.as_str(),
                        Some("service" | "network" | "server" | "auto-share")
                    )
                })
            {
                return Err("offline FS host requires extraction without service features".into());
            }
        }
        if name == "gnunet"
            && !array(node, "features")?
                .iter()
                .any(|value| value == "official-fs-extraction")
        {
            return Err("offline FS facade extraction feature absent".into());
        }
        seen.insert(name);
        for dependency in array(node, "deps")? {
            if !array(dependency, "dep_kinds")?
                .iter()
                .any(|kind| kind["kind"].is_null())
            {
                continue;
            }
            let dependency_id = field(dependency, "pkg")?;
            let target = packages
                .get(dependency_id)
                .ok_or("offline FS dependency package absent")?;
            let proc_macro = array(target, "targets")?.iter().any(|target| {
                target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "proc-macro"))
            });
            if !proc_macro {
                pending.push((dependency_id, path.clone()));
            }
        }
    }
    for required in ["gnunet-fs-host", "gnunet-extractor-host"] {
        if !seen.contains(required) {
            return Err(format!("offline FS fixture omits required package: {required}").into());
        }
    }
    if (feature == "facade") != seen.contains("gnunet") {
        return Err("offline FS fixture selected the wrong SDK entry point".into());
    }
    Ok(())
}

fn validate_metadata_codec_boundary(meta: &Value) -> CheckResult<()> {
    let packages = members(meta)?;
    for (package_name, feature, expected) in [
        ("gnunet", "fs-codec", &["dep:gnunet-fs-codec"][..]),
        (
            "gnunet",
            "fs-compression",
            &["alloc", "fs-codec", "gnunet-fs-codec/alloc"][..],
        ),
        ("gnunet-fs-codec", "alloc", &["miniz_oxide/with-alloc"][..]),
        (
            "gnunet-compression",
            "alloc",
            &["dep:miniz_oxide", "miniz_oxide/with-alloc"][..],
        ),
        (
            "gnunet-setu",
            "zlib",
            &[
                "alloc",
                "dep:gnunet-compression",
                "gnunet-compression/alloc",
            ][..],
        ),
    ] {
        let package = packages
            .iter()
            .find(|p| p["name"] == package_name)
            .ok_or("metadata codec package absent")?;
        let actual: BTreeSet<_> = package["features"][feature]
            .as_array()
            .ok_or("metadata codec feature absent")?
            .iter()
            .map(|v| v.as_str().ok_or("metadata codec feature member absent"))
            .collect::<Result<_, _>>()?;
        if actual != expected.iter().copied().collect() {
            return Err(format!(
                "metadata codec allocation boundary changed: {package_name}/{feature}"
            )
            .into());
        }
    }
    Ok(())
}
fn validate_features(meta: &Value) -> CheckResult<()> {
    for package in members(meta)? {
        let name = field(package, "name")?;
        let features = package["features"]
            .as_object()
            .ok_or("features object absent")?;
        if features
            .get("default")
            .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
        {
            return Err(format!("default features must be empty: {name}").into());
        }
        for (feature, dependencies) in features {
            if forbidden_feature(feature) {
                return Err(format!("removed private feature: {name}/{feature}").into());
            }
            for dependency in dependencies.as_array().ok_or("feature list absent")? {
                let dependency = dependency
                    .as_str()
                    .ok_or("feature member is not a string")?;
                if forbidden_feature(dependency) {
                    return Err(format!("private feature forwarding: {name}/{dependency}").into());
                }
            }
        }
    }
    Ok(())
}

// PILS native support is an explicit SDK opt-in. Service-only users must not
// acquire a client/heap/Resolver dependency through feature forwarding.
fn validate_pils_feature_boundary(meta: &Value) -> CheckResult<()> {
    let facade = members(meta)?
        .into_iter()
        .find(|p| p["name"] == "gnunet")
        .ok_or("facade absent")?;
    for (name, required) in [
        ("official-pils", &["std", "dep:gnunet-pils-host"][..]),
        (
            "official-pils-client",
            &[
                "official-pils",
                "official-client",
                "gnunet-pils-host/client",
            ][..],
        ),
    ] {
        let actual = facade["features"][name]
            .as_array()
            .ok_or("PILS SDK feature absent")?
            .iter()
            .map(|v| v.as_str().ok_or("feature member absent"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual != required.iter().copied().collect() {
            return Err(format!("PILS SDK feature boundary changed: {name}").into());
        }
    }
    Ok(())
}

// DHT is an isolated client opt-in; std/alloc aliases cannot silently activate
// another native host or a Resolver broker behind its two-member public feature.
fn validate_dht_client_feature_boundary(meta: &Value) -> CheckResult<()> {
    validate_isolated_client_feature(meta, "official-dht-client", "gnunet-dht-client-host")
}
fn validate_gns_client_feature_boundary(meta: &Value) -> CheckResult<()> {
    validate_isolated_client_feature(meta, "official-gns-client", "gnunet-gns-client-host")
}
fn validate_isolated_client_feature(meta: &Value, feature: &str, host: &str) -> CheckResult<()> {
    let facade = members(meta)?
        .into_iter()
        .find(|p| p["name"] == "gnunet")
        .ok_or("facade absent")?;
    let features = facade["features"]
        .as_object()
        .ok_or("facade features absent")?;
    let direct = features
        .get(feature)
        .and_then(Value::as_array)
        .ok_or("isolated client SDK feature absent")?;
    let actual = direct
        .iter()
        .map(|v| v.as_str().ok_or("isolated client feature member absent"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let direct_host = format!("dep:{host}");
    if actual != ["std", direct_host.as_str()].into_iter().collect() {
        return Err("isolated SDK feature must activate only std and its client host".into());
    }
    let mut hosts = BTreeMap::new();
    for dep in array(facade, "dependencies")? {
        let name = field(dep, "name")?;
        if POLICIES.iter().any(|p| p.name == name && !p.core) {
            hosts.insert(dep["rename"].as_str().unwrap_or(name), name);
        }
    }
    let mut pending = vec![feature];
    let mut seen = BTreeSet::new();
    let mut active = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name) {
            continue;
        }
        for value in features
            .get(name)
            .and_then(Value::as_array)
            .ok_or("SDK feature alias absent")?
        {
            let value = value.as_str().ok_or("SDK feature member absent")?;
            if let Some(dep) = value.strip_prefix("dep:") {
                if let Some(host) = hosts.get(dep) {
                    active.insert(*host);
                }
            } else if let Some((dep, _)) = value.split_once('/') {
                if !dep.ends_with('?')
                    && let Some(host) = hosts.get(dep)
                {
                    active.insert(*host);
                }
            } else if features.contains_key(value) {
                pending.push(value);
            }
        }
    }
    if active != [host].into_iter().collect() {
        return Err("isolated SDK alias activates an unrelated native host/Resolver".into());
    }
    Ok(())
}

pub(crate) fn check_lints() -> CheckResult<()> {
    let meta = metadata()?;
    for package in members(&meta)? {
        let rule = policy(field(package, "name")?)?;
        let path = Path::new(field(package, "manifest_path")?);
        let manifest = fs::read_to_string(path)?;
        for required in [
            "[lints]\nworkspace = true",
            "edition.workspace = true",
            "rust-version.workspace = true",
        ] {
            if !manifest.contains(required) {
                return Err(format!("{} lacks {required}", path.display()).into());
            }
        }
        if rule.core {
            let library = fs::read_to_string(
                path.parent()
                    .ok_or("manifest parent absent")?
                    .join("src/lib.rs"),
            )?;
            validate_core_source(rule.name, &library)?;
        }
    }
    validate_core_source(
        "embedded noalloc fixture",
        &fs::read_to_string("tests/embedded/noalloc/src/lib.rs")?,
    )?;
    Ok(())
}
fn validate_core_source(name: &str, source: &str) -> CheckResult<()> {
    for required in ["#![no_std]", "#![forbid(unsafe_code)]"] {
        if !source.lines().any(|line| line.trim() == required) {
            return Err(format!("{name} lacks active {required}").into());
        }
    }
    Ok(())
}

/// Follow target normal dependencies only; host build/proc-macro features are
/// not target allocations. Check both actual independent embedded graphs.
pub(crate) fn check_noalloc() -> CheckResult<()> {
    for target in EMBEDDED_TARGETS {
        let meta = metadata_args(&[
            "metadata",
            "--manifest-path",
            "tests/embedded/noalloc/Cargo.toml",
            "--format-version",
            "1",
            "--filter-platform",
            target,
            "--locked",
            "--offline",
        ])?;
        validate_noalloc_graph(&meta)?;
    }
    Ok(())
}
fn validate_noalloc_graph(meta: &Value) -> CheckResult<()> {
    let packages: BTreeMap<_, _> = array(meta, "packages")?
        .iter()
        .map(|package| Ok((field(package, "id")?, package)))
        .collect::<CheckResult<_>>()?;
    let nodes: BTreeMap<_, _> = array(&meta["resolve"], "nodes")?
        .iter()
        .map(|node| Ok((field(node, "id")?, node)))
        .collect::<CheckResult<_>>()?;
    let root = field(&meta["resolve"], "root")?;
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    let mut core = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages.get(id).ok_or("resolved package absent")?;
        let node = nodes.get(id).ok_or("resolved node absent")?;
        let name = field(package, "name")?;
        let path = field(package, "manifest_path")?;
        if path.contains("/adapters/")
            || path.contains("/apps/")
            || c_gnunet(name)
            || matches!(name, "tokio" | "async-io")
        {
            return Err(format!("noalloc graph includes platform package: {name}").into());
        }
        if name == "gnunet" || name.starts_with("gnunet-") {
            core.insert(name);
        }
        for feature in array(node, "features")? {
            let feature = feature.as_str().ok_or("resolved feature is not a string")?;
            if matches!(feature, "alloc" | "std" | "with-alloc") || forbidden_feature(feature) {
                return Err(format!("noalloc graph enables {name}/{feature}").into());
            }
        }
        for dependency in array(node, "deps")? {
            if !array(dependency, "dep_kinds")?
                .iter()
                .any(|kind| kind["kind"].is_null())
            {
                continue;
            }
            let dependency_id = field(dependency, "pkg")?;
            let target = packages
                .get(dependency_id)
                .ok_or("dependency package absent")?;
            let proc_macro = array(target, "targets")?.iter().any(|target| {
                target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "proc-macro"))
            });
            if !proc_macro {
                pending.push(dependency_id);
            }
        }
    }
    for required in [
        "gnunet-transport-quic",
        "gnunet-transport-dv-crypto",
        "gnunet-unix-communicator",
        "gnunet-dns-interception",
        "gnunet-hostlist",
        "gnunet-testbed",
        "gnunet-pt",
        "gnunet-namestore",
        "gnunet-reclaim",
        "gnunet-reclaim-credentials",
        "gnunet-rest",
        "gnunet-gnsrecord-text",
        "gnunet-json",
        "gnunet-messenger",
        "gnunet-messenger-core",
        "gnunet-revocation",
        "gnunet-topology",
        "gnunet-nat",
        "gnunet-did",
        "gnunet-datacache",
        "gnunet-namecache",
        "gnunet-identity",
        "gnunet-regex",
        "gnunet-regex-service",
        "gnunet-vpn",
        "gnunet-exit",
        "gnunet-seti",
        "gnunet-setu",
        "gnunet-peerstore",
        "gnunet",
        "gnunet-cadet",
        "gnunet-fs-codec",
        "gnunet-fs",
        "gnunet-datastore",
        "gnunet-types",
        "gnunet-resources",
        "gnunet-wire",
        "gnunet-crypto",
        "gnunet-client",
        "gnunet-gnsrecord",
        "gnunet-gnscrypto",
        "gnunet-gns",
        "gnunet-hello",
        "gnunet-block",
        "gnunet-dns",
        "gnunet-idna",
        "gnunet-resolver-service-core",
        "gnunet-arm-core",
        "gnunet-arm-service-core",
        "gnunet-session-crypto",
        "gnunet-tcp-communicator-core",
        "gnunet-dnsstub",
        "gnunet-statistics",
        "gnunet-core",
        "gnunet-pils",
        "gnunet-transport",
    ] {
        if !core.contains(required) {
            return Err(format!("noalloc fixture omits required core package: {required}").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let packages: Vec<_> = POLICIES.iter().map(|rule| serde_json::json!({"id":rule.name,"name":rule.name,"manifest_path":format!("/workspace/{}/Cargo.toml",rule.directory),"features":{"default":[]},"dependencies":[],"links":null})).collect();
        serde_json::json!({"workspace_root":"/workspace","workspace_members":packages.iter().map(|p|p["id"].clone()).collect::<Vec<_>>(),"packages":packages})
    }
    #[test]
    fn renamed_optional_target_and_test_dependencies_cannot_hide_ffi_or_layer_edges()
    -> CheckResult<()> {
        for (owner, dependency, accepted) in [
            ("gnunet-crypto", "sha2", true),
            ("gnunet-client", "tokio", false),
            ("gnunet-wire", "gnunet", false),
            ("gnunet-cli", "libgnunet", false),
            ("xtask", "gnunet-sys", false),
        ] {
            for kind in [Value::Null, "dev".into(), "build".into()] {
                let mut meta = fixture();
                let package = meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|p| p["name"] == owner)
                    .ok_or("owner absent")?;
                package["dependencies"] = serde_json::json!([{"name":dependency,"rename":"innocent_alias","kind":kind,"target":"cfg(unix)","optional":true,"features":[]}]);
                if validate_dependencies(&meta).is_ok() != accepted {
                    return Err(format!("wrong edge decision for {owner} -> {dependency}").into());
                }
            }
        }
        let mut meta = fixture();
        meta["packages"]
            .as_array_mut()
            .ok_or("packages absent")?
            .remove(0);
        if validate_dependencies(&meta).is_ok() {
            return Err("missing core package accepted".into());
        }
        Ok(())
    }
    #[test]
    fn shared_framing_wire_edge_cannot_hide_a_normal_domain_dependency() -> CheckResult<()> {
        for (kind, accepted) in [
            (Value::Null, false),
            ("dev".into(), true),
            ("build".into(), true),
        ] {
            let mut meta = fixture();
            for (source, target, edge_kind) in [
                ("gnunet-service-runtime", "gnunet-wire", Value::Null),
                ("gnunet-wire", "gnunet-transport", kind),
            ] {
                let package = meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|p| p["name"] == source)
                    .ok_or("package absent")?;
                package["dependencies"] = serde_json::json!([{
                    "name":target, "rename":"framing_alias", "kind":edge_kind,
                    "target":"cfg(unix)", "optional":true, "features":[]
                }]);
            }
            let result = validate_generic_runtime_boundary(&meta);
            if result.is_ok() != accepted {
                return Err(format!("wrong framing closure decision: {result:?}").into());
            }
            if let Err(error) = result
                && !error
                    .to_string()
                    .contains("gnunet-service-runtime -> gnunet-wire -> gnunet-transport")
            {
                return Err(format!("missing original framing dependency path: {error}").into());
            }
        }
        Ok(())
    }
    #[test]
    fn generic_runtime_production_closure_rejects_domain_edges_but_ignores_dev_only()
    -> CheckResult<()> {
        for (owner, dependency, kind, rejected_path) in [
            (
                "gnunet-service-runtime",
                "gnunet-statistics",
                Value::Null,
                Some("gnunet-service-runtime -> gnunet-statistics"),
            ),
            (
                "gnunet-native",
                "gnunet-client",
                Value::Null,
                Some("gnunet-service-runtime -> gnunet-config -> gnunet-native -> gnunet-client"),
            ),
            ("gnunet-native", "gnunet-client", "dev".into(), None),
            ("gnunet-native", "gnunet-client", "build".into(), None),
            ("gnunet-native", "gnunet-resources", Value::Null, None),
            ("gnunet-native", "gnunet-gnsrecord", Value::Null, None),
            (
                "gnunet-native",
                "gnunet-namecache",
                Value::Null,
                Some(
                    "gnunet-service-runtime -> gnunet-config -> gnunet-native -> gnunet-namecache",
                ),
            ),
        ] {
            let mut meta = fixture();
            for (source, target, edge_kind) in [
                ("gnunet-service-runtime", "gnunet-config", Value::Null),
                ("gnunet-config", "gnunet-native", Value::Null),
                (owner, dependency, kind),
            ] {
                let package = meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|package| package["name"] == source)
                    .ok_or("runtime fixture package absent")?;
                package["dependencies"] = serde_json::json!([{
                    "name":target,"rename":"innocent_alias","kind":edge_kind,
                    "target":"cfg(unix)","optional":true,"features":[]
                }]);
            }
            match (validate_generic_runtime_boundary(&meta), rejected_path) {
                (Ok(()), None) => {}
                (Err(error), Some(path)) if error.to_string().contains(path) => {}
                (result, expected) => {
                    return Err(format!(
                        "wrong generic runtime closure decision: {result:?}; expected path {expected:?}"
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
    #[test]
    fn shared_io_closures_reject_business_edges_and_inverted_broker_cycle() -> CheckResult<()> {
        for (root, mid, end, kind, reject) in [
            (
                "gnunet-client-host",
                "gnunet-wire",
                "gnunet-gnsrecord",
                Value::Null,
                false,
            ),
            (
                "gnunet-client-host",
                "gnunet-wire",
                "gnunet-namecache",
                Value::Null,
                true,
            ),
            (
                "gnunet-tcp-communicator-runtime",
                "gnunet-pils-host",
                "gnunet-types",
                Value::Null,
                false,
            ),
            (
                "gnunet-tcp-communicator-runtime",
                "gnunet-transport-host",
                "gnunet-types",
                Value::Null,
                true,
            ),
            (
                "gnunet-tcp-communicator-runtime",
                "gnunet-pils-host",
                "gnunet-transport-host",
                Value::Null,
                true,
            ),
            (
                "gnunet-tcp-communicator-runtime",
                "gnunet-core-client-host",
                "gnunet-types",
                Value::Null,
                true,
            ),
            (
                "gnunet-tcp-communicator-runtime",
                "gnunet-udp-communicator-host",
                "gnunet-types",
                Value::Null,
                true,
            ),
            (
                "gnunet-transport-runtime",
                "gnunet-core-host",
                "gnunet-types",
                Value::Null,
                true,
            ),
            (
                "gnunet-transport-runtime",
                "gnunet-transport-host",
                "gnunet-types",
                Value::Null,
                false,
            ),
            (
                "gnunet-transport-runtime",
                "gnunet-pils-host",
                "gnunet-types",
                Value::Null,
                false,
            ),
            (
                "gnunet-transport-runtime",
                "gnunet-transport-host",
                "gnunet-statistics",
                Value::Null,
                true,
            ),
            (
                "gnunet-nse-host",
                "gnunet-core-host",
                "gnunet-types",
                Value::Null,
                true,
            ),
            (
                "gnunet-nse-host",
                "gnunet-pils-host",
                "gnunet-transport-host",
                Value::Null,
                true,
            ),
            (
                "gnunet-core-client-host",
                "gnunet-client",
                "gnunet-statistics",
                Value::Null,
                true,
            ),
            (
                "gnunet-core-client-host",
                "gnunet-client",
                "gnunet-statistics",
                "dev".into(),
                false,
            ),
            (
                "gnunet-core-host",
                "gnunet-pils-host",
                "gnunet-statistics",
                Value::Null,
                true,
            ),
            (
                "gnunet-transport-host",
                "gnunet-transport",
                "gnunet-ipc-unix",
                Value::Null,
                true,
            ),
            (
                "gnunet-tcp-communicator-host",
                "gnunet-session-crypto",
                "gnunet-statistics",
                Value::Null,
                true,
            ),
            (
                "gnunet-resolver-broker",
                "gnunet-client-host",
                "gnunet-ipc-unix",
                Value::Null,
                true,
            ),
            (
                "gnunet-client-host",
                "gnunet-service-runtime",
                "gnunet-resolver-broker",
                Value::Null,
                true,
            ),
            (
                "gnunet-client-host",
                "gnunet-service-runtime",
                "gnunet-resolver-broker",
                "dev".into(),
                false,
            ),
            (
                "gnunet-client-host",
                "gnunet-service-runtime",
                "gnunet-resolver-broker",
                "build".into(),
                false,
            ),
            (
                "gnunet-udp-communicator-host",
                "gnunet-session-crypto",
                "gnunet-transport-host",
                Value::Null,
                true,
            ),
            (
                "gnunet-udp-communicator-host",
                "gnunet-session-crypto",
                "gnunet-transport-host",
                "dev".into(),
                false,
            ),
        ] {
            let mut meta = fixture();
            for (owner, target, edge_kind) in [(root, mid, Value::Null), (mid, end, kind)] {
                let package = meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|p| p["name"] == owner)
                    .ok_or("fixture owner absent")?;
                package["dependencies"] = serde_json::json!([{"name":target,"rename":"harmless_alias","kind":edge_kind,"target":"cfg(unix)","optional":true,"features":[]}]);
            }
            if validate_shared_io_boundaries(&meta).is_err() != reject {
                return Err(
                    format!("wrong shared I/O edge decision for {root} -> {mid} -> {end}").into(),
                );
            }
        }
        let mut missing = fixture();
        missing["packages"]
            .as_array_mut()
            .ok_or("packages absent")?
            .retain(|p| p["name"] != "gnunet-client-host");
        if validate_shared_io_boundaries(&missing).is_ok() {
            return Err("missing CLIENT package accepted".into());
        }
        Ok(())
    }
    #[test]
    fn default_and_removed_private_feature_forwarding_are_rejected() -> CheckResult<()> {
        validate_features(&fixture())?;
        for features in [
            serde_json::json!({"default":["std"]}),
            serde_json::json!({"default":[],"legacy-native":[]}),
            serde_json::json!({"default":[],"alias":["dep?/full"]}),
            serde_json::json!({"default":[],"no_std":[]}),
        ] {
            let mut meta = fixture();
            meta["packages"][0]["features"] = features;
            if validate_features(&meta).is_ok() {
                return Err("private/default feature bypass accepted".into());
            }
        }
        if validate_core_source("bad", "// #![no_std]\n#![forbid(unsafe_code)]").is_ok() {
            return Err("commented no_std guard accepted".into());
        }
        Ok(())
    }
    #[test]
    fn pils_native_feature_cannot_leak_into_service_or_omit_client_activation() -> CheckResult<()> {
        let mut meta = fixture();
        let facade = meta["packages"]
            .as_array_mut()
            .ok_or("packages absent")?
            .iter_mut()
            .find(|p| p["name"] == "gnunet")
            .ok_or("facade absent")?;
        facade["features"] = serde_json::json!({"default":[],"official-pils":["std","dep:gnunet-pils-host"],"official-pils-client":["official-pils","official-client","gnunet-pils-host/client"]});
        validate_pils_feature_boundary(&meta)?;
        for (name, bad) in [
            (
                "official-pils",
                serde_json::json!(["std", "dep:gnunet-pils-host", "gnunet-pils-host/client"]),
            ),
            (
                "official-pils-client",
                serde_json::json!(["official-pils", "official-client"]),
            ),
        ] {
            let mut bad_meta = meta.clone();
            let facade = bad_meta["packages"]
                .as_array_mut()
                .ok_or("packages absent")?
                .iter_mut()
                .find(|p| p["name"] == "gnunet")
                .ok_or("facade absent")?;
            facade["features"][name] = bad;
            if validate_pils_feature_boundary(&bad_meta).is_ok() {
                return Err("PILS feature isolation bypass accepted".into());
            }
        }
        Ok(())
    }
    #[test]
    fn independent_client_features_reject_direct_and_transitive_native_alias_leaks()
    -> CheckResult<()> {
        for (feature, host) in [
            ("official-dht-client", "gnunet-dht-client-host"),
            ("official-gns-client", "gnunet-gns-client-host"),
        ] {
            let mut meta = fixture();
            let facade = meta["packages"]
                .as_array_mut()
                .ok_or("packages absent")?
                .iter_mut()
                .find(|p| p["name"] == "gnunet")
                .ok_or("facade absent")?;
            facade["features"] = serde_json::json!({"default":[],"alloc":[],"std":["alloc"],feature:["std",format!("dep:{host}")]});
            facade["dependencies"] = serde_json::json!([
                {"name":host,"optional":true,"rename":null},
                {"name":"gnunet-resolver-broker","optional":true,"rename":"innocent_alias"}
            ]);
            validate_isolated_client_feature(&meta, feature, host)?;
            for (name, bad) in [
                (
                    feature,
                    serde_json::json!(["std", "official-client", format!("dep:{host}")]),
                ),
                (feature, serde_json::json!(["std"])),
                ("std", serde_json::json!(["alloc", "dep:innocent_alias"])),
                ("alloc", serde_json::json!(["innocent_alias/runtime"])),
            ] {
                let mut bad_meta = meta.clone();
                let facade = bad_meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|p| p["name"] == "gnunet")
                    .ok_or("facade absent")?;
                facade["features"][name] = bad;
                if validate_isolated_client_feature(&bad_meta, feature, host).is_ok() {
                    return Err(format!("{feature} SDK native alias leak accepted").into());
                }
            }
        }
        Ok(())
    }
    #[test]
    fn core_host_adapters_must_remain_optional() -> CheckResult<()> {
        for dependency in [
            "gnunet-resolver-broker",
            "gnunet-arm-host",
            "gnunet-arm-service-host",
            "gnunet-service-runtime",
            "gnunet-ipc-unix",
            "gnunet-config",
            "gnunet-statistics-store",
            "gnunet-dnsstub-host",
        ] {
            for optional in [true, false] {
                let mut metadata = fixture();
                let core = metadata["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|package| package["name"] == "gnunet")
                    .ok_or("facade absent")?;
                core["dependencies"] =
                    serde_json::json!([{"name":dependency,"optional":optional,"features":[]}]);
                if validate_dependencies(&metadata).is_ok() != optional {
                    return Err(format!("host optional boundary failed for {dependency}").into());
                }
            }
        }
        Ok(())
    }
    fn fs_extraction_fixture(feature: &str) -> Value {
        let packages: Vec<_> = [
            (
                "fixture",
                "gnunet-fs-extraction-check",
                "tests/features/fs-extraction",
            ),
            ("fs", "gnunet-fs-host", "adapters/fs-std"),
            (
                "extractor",
                "gnunet-extractor-host",
                "adapters/extractor-std",
            ),
            ("facade", "gnunet", "crates/gnunet"),
            ("helper", "offline-helper", "crates/offline-helper"),
            ("target", "gnunet-client-host", "crates/renamed-dependency"),
        ]
        .into_iter()
        .map(|(id, name, directory)| {
            serde_json::json!({
                "id":id,"name":name,"manifest_path":format!("/workspace/{directory}/Cargo.toml"),
                "targets":[{"kind":["lib"]}]
            })
        })
        .collect();
        let root_dependency = if feature == "facade" { "facade" } else { "fs" };
        serde_json::json!({
            "packages":packages,
            "resolve":{"root":"fixture","nodes":[
                {"id":"fixture","features":[feature],"deps":[{"name":"selected_sdk","pkg":root_dependency,"dep_kinds":[{"kind":null}]}]},
                {"id":"fs","features":["extraction"],"deps":[{"name":"extractor","pkg":"extractor","dep_kinds":[{"kind":null}]}]},
                {"id":"extractor","features":[],"deps":[]},
                {"id":"facade","features":["official-fs-extraction"],"deps":[{"name":"fs","pkg":"fs","dep_kinds":[{"kind":null}]}]},
                {"id":"helper","features":[],"deps":[{"name":"innocent_alias","pkg":"target","dep_kinds":[{"kind":null}]}]},
                {"id":"target","features":[],"deps":[]}
            ]}
        })
    }

    #[test]
    fn fs_extraction_resolved_graph_rejects_renamed_transitive_runtime_leaks() -> CheckResult<()> {
        for feature in ["host", "facade"] {
            for forbidden in [
                "gnunet-client-host",
                "gnunet-datastore-host",
                "gnunet-service-runtime",
                "tokio",
            ] {
                let mut meta = fs_extraction_fixture(feature);
                validate_fs_extraction_graph(&meta, feature)?;
                let package = meta["packages"]
                    .as_array_mut()
                    .ok_or("packages absent")?
                    .iter_mut()
                    .find(|package| package["id"] == "target")
                    .ok_or("renamed package absent")?;
                package["name"] = forbidden.into();
                let fs = meta["resolve"]["nodes"]
                    .as_array_mut()
                    .ok_or("nodes absent")?
                    .iter_mut()
                    .find(|node| node["id"] == "fs")
                    .ok_or("FS node absent")?;
                fs["deps"].as_array_mut().ok_or("dependencies absent")?.push(
                    serde_json::json!({"name":"ordinary_metadata","pkg":"helper","dep_kinds":[{"kind":null}]})
                );
                match validate_fs_extraction_graph(&meta, feature) {
                    Err(error)
                        if error.to_string().contains(&format!(
                            "gnunet-fs-host -> offline-helper -> {forbidden}"
                        )) => {}
                    result => {
                        return Err(format!(
                            "wrong offline extraction dependency decision: {result:?}"
                        )
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fs_extraction_resolved_graph_ignores_dev_build_and_host_macro_closures() -> CheckResult<()> {
        for feature in ["host", "facade"] {
            for (kind, proc_macro) in [
                ("dev".into(), false),
                ("build".into(), false),
                (Value::Null, true),
            ] {
                let mut meta = fs_extraction_fixture(feature);
                let fs = meta["resolve"]["nodes"]
                    .as_array_mut()
                    .ok_or("nodes absent")?
                    .iter_mut()
                    .find(|node| node["id"] == "fs")
                    .ok_or("FS node absent")?;
                fs["deps"].as_array_mut().ok_or("dependencies absent")?.push(
                    serde_json::json!({"name":"host_only","pkg":"helper","dep_kinds":[{"kind":kind}]})
                );
                if proc_macro {
                    let helper = meta["packages"]
                        .as_array_mut()
                        .ok_or("packages absent")?
                        .iter_mut()
                        .find(|package| package["id"] == "helper")
                        .ok_or("host macro package absent")?;
                    helper["targets"] = serde_json::json!([{"kind":["proc-macro"]}]);
                }
                validate_fs_extraction_graph(&meta, feature)?;
            }
        }
        let mut empty = fs_extraction_fixture("host");
        empty["resolve"]["nodes"][0]["deps"] = serde_json::json!([]);
        if validate_fs_extraction_graph(&empty, "host").is_ok() {
            return Err("empty offline extraction fixture accepted".into());
        }
        Ok(())
    }

    #[test]
    fn noalloc_graph_excludes_host_macros_but_rejects_target_std_or_missing_core() -> CheckResult<()>
    {
        let names = [
            "fixture",
            "gnunet-transport-quic",
            "gnunet-transport-dv-crypto",
            "gnunet-unix-communicator",
            "gnunet-dns-interception",
            "gnunet-hostlist",
            "gnunet-testbed",
            "gnunet-pt",
            "gnunet-namestore",
            "gnunet-reclaim",
            "gnunet-reclaim-credentials",
            "gnunet-rest",
            "gnunet-gnsrecord-text",
            "gnunet-json",
            "gnunet-messenger",
            "gnunet-messenger-core",
            "gnunet-revocation",
            "gnunet-nat",
            "gnunet-topology",
            "gnunet-did",
            "gnunet-datacache",
            "gnunet-namecache",
            "gnunet-identity",
            "gnunet-regex",
            "gnunet-regex-service",
            "gnunet-vpn",
            "gnunet-exit",
            "gnunet-seti",
            "gnunet-setu",
            "gnunet-peerstore",
            "gnunet",
            "gnunet-cadet",
            "gnunet-fs-codec",
            "miniz_oxide",
            "adler2",
            "gnunet-fs",
            "gnunet-datastore",
            "gnunet-types",
            "gnunet-resources",
            "gnunet-wire",
            "gnunet-crypto",
            "gnunet-client",
            "gnunet-gnsrecord",
            "gnunet-gnscrypto",
            "gnunet-gns",
            "gnunet-hello",
            "gnunet-block",
            "gnunet-dns",
            "gnunet-idna",
            "gnunet-resolver-service-core",
            "gnunet-arm-core",
            "gnunet-arm-service-core",
            "gnunet-session-crypto",
            "gnunet-tcp-communicator-core",
            "gnunet-dnsstub",
            "gnunet-statistics",
            "gnunet-core",
            "gnunet-pils",
            "gnunet-transport",
            "host-macro",
        ];
        let mut packages = Vec::new();
        let mut nodes = Vec::new();
        for name in names {
            packages.push(serde_json::json!({"id":name,"name":name,"manifest_path":format!("/workspace/crates/{name}/Cargo.toml"),"targets":[{"kind":[if name=="host-macro" {"proc-macro"}else{"lib"}]}]}));
            let deps: Vec<_> = if name == "fixture" {
                names[1..]
                    .iter()
                    .map(|dep| serde_json::json!({"pkg":dep,"dep_kinds":[{"kind":null}]}))
                    .collect()
            } else {
                Vec::new()
            };
            nodes.push(serde_json::json!({"id":name,"features":if name=="host-macro" {vec!["std"]}else{vec![]},"deps":deps}));
        }
        let meta =
            serde_json::json!({"packages":packages,"resolve":{"root":"fixture","nodes":nodes}});
        validate_noalloc_graph(&meta)?;
        let mut target_std = meta.clone();
        target_std["resolve"]["nodes"][2]["features"] = serde_json::json!(["std"]);
        if validate_noalloc_graph(&target_std).is_ok() {
            return Err("target std accepted".into());
        }
        let mut compressor_alloc = meta.clone();
        let miniz = compressor_alloc["resolve"]["nodes"]
            .as_array_mut()
            .ok_or("nodes absent")?
            .iter_mut()
            .find(|node| node["id"] == "miniz_oxide")
            .ok_or("miniz absent")?;
        miniz["features"] = serde_json::json!(["with-alloc"]);
        if validate_noalloc_graph(&compressor_alloc).is_ok() {
            return Err("miniz hidden compressor allocation accepted".into());
        }
        let mut omitted = meta;
        omitted["resolve"]["nodes"][0]["deps"] = serde_json::json!([]);
        if validate_noalloc_graph(&omitted).is_ok() {
            return Err("empty fixture accepted".into());
        }
        Ok(())
    }
}
