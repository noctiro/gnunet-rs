//! Compile enabled desktop SDK entry points without opening native resources.
#![cfg(any(unix, windows))]

macro_rules! desktop_api {
    ($feature:meta, $path:path) => {
        #[cfg($feature)]
        pub use $path;
    };
}

desktop_api!(
    feature = "official-quic-communicator",
    gnunet::quic_communicator_host
);
desktop_api!(
    feature = "official-transport-dv-bridge",
    gnunet::transport_dv_bridge
);
desktop_api!(
    feature = "official-transport-dv-runtime",
    gnunet::transport_dv_runtime
);
desktop_api!(
    feature = "official-transport-dv-store",
    gnunet::transport_dv_store
);
desktop_api!(
    feature = "official-transport-server",
    gnunet::transport_service
);
desktop_api!(
    feature = "official-transport-dv-crypto",
    gnunet::transport_dv_crypto_host
);
desktop_api!(feature = "unix-communicator", gnunet::unix_communicator);
desktop_api!(feature = "official-dns-tools", gnunet::dns_tools);
desktop_api!(feature = "official-dns-server", gnunet::dns_service);
desktop_api!(feature = "official-hostlist", gnunet::hostlist_host);
desktop_api!(feature = "official-testbed", gnunet::testbed_host);
desktop_api!(feature = "official-pt", gnunet::pt_host);
desktop_api!(
    feature = "official-revocation-server",
    gnunet::revocation_host
);
desktop_api!(
    feature = "official-namestore-server",
    gnunet::namestore_host
);
desktop_api!(feature = "official-rest-oidc", gnunet::oidc_crypto);
desktop_api!(feature = "official-rest-server", gnunet::rest_host);
desktop_api!(feature = "official-zoneimport", gnunet::zoneimport_host);
desktop_api!(
    feature = "official-namecache-server",
    gnunet::namecache_host
);
desktop_api!(feature = "official-identity-server", gnunet::identity_host);
desktop_api!(feature = "official-arm", gnunet::arm_host);
desktop_api!(
    any(feature = "official-arm", feature = "official-arm-server"),
    gnunet::arm_service_host
);
desktop_api!(feature = "official-core", gnunet::core_host);
desktop_api!(feature = "official-exit", gnunet::exit_host);
desktop_api!(feature = "official-nse", gnunet::nse_host);
desktop_api!(
    feature = "official-peerstore-server",
    gnunet::peerstore_host
);
desktop_api!(feature = "official-pils", gnunet::pils_host);
desktop_api!(feature = "official-program", gnunet::program);
desktop_api!(feature = "official-resolver", gnunet::resolver_host);
desktop_api!(feature = "official-service", gnunet::service_runtime);
desktop_api!(feature = "official-service", gnunet::service_startup);
desktop_api!(feature = "official-transport", gnunet::transport_host);
desktop_api!(feature = "official-tun", gnunet::tun);
desktop_api!(feature = "official-vpn-server", gnunet::vpn_host);
desktop_api!(feature = "official-tcp", gnunet::tcp_host);
desktop_api!(
    feature = "official-secretsharing-decrypt",
    gnunet::secretsharing_decrypt_host
);
desktop_api!(
    feature = "official-secretsharing-keygen",
    gnunet::secretsharing_keygen_host
);
desktop_api!(feature = "official-uri-dispatch", gnunet::uri_dispatch);
desktop_api!(feature = "official-qr", gnunet::qr_host);
desktop_api!(
    feature = "official-messenger-api",
    gnunet::clients::messenger_api
);
