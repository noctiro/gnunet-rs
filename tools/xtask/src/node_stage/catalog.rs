//! Native packages and their destinations in the staged prefix.
use super::{Platform, Target};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Location {
    Bin,
    Libexec,
    Nss,
}

impl Location {
    pub(super) const fn directory(self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Libexec => "lib/gnunet/libexec",
            Self::Nss => "lib",
        }
    }
}

pub(super) struct Package {
    pub directory: &'static str,
    location: Location,
    names: &'static [&'static str],
    extra: &'static [(&'static str, Location, Availability)],
    pub features: Option<&'static str>,
    platform: Availability,
}

#[derive(Clone, Copy)]
pub(super) enum Availability {
    All,
    Unix,
    Linux,
    LinuxGnu,
    Windows,
}

impl Availability {
    pub(super) fn supports(self, target: &Target) -> bool {
        match self {
            Self::All => true,
            Self::Unix => target.platform() != Platform::Windows,
            Self::Linux => target.platform() == Platform::Linux,
            Self::LinuxGnu => target.linux_gnu(),
            Self::Windows => target.platform() == Platform::Windows,
        }
    }
}

impl Package {
    const fn new(directory: &'static str, location: Location) -> Self {
        Self {
            directory,
            location,
            names: &[],
            extra: &[],
            features: None,
            platform: Availability::All,
        }
    }

    const fn names(mut self, names: &'static [&'static str]) -> Self {
        self.names = names;
        self
    }

    const fn features(mut self, features: &'static str) -> Self {
        self.features = Some(features);
        self
    }

    const fn extra(mut self, extra: &'static [(&'static str, Location, Availability)]) -> Self {
        self.extra = extra;
        self
    }

    const fn on(mut self, platform: Availability) -> Self {
        self.platform = platform;
        self
    }

    pub(super) fn artifacts(
        &self,
        target: &Target,
    ) -> impl Iterator<Item = (&'static str, Location)> {
        let package_dir = self.directory.rsplit('/').next();
        let default = package_dir.filter(|_| self.names.is_empty());
        let extra = self.extra.iter().filter_map(|&(name, location, platform)| {
            platform.supports(target).then_some((name, location))
        });
        default
            .into_iter()
            .chain(self.names.iter().copied())
            .map(|name| (name, self.location))
            .chain(extra)
    }
}

const fn bin(directory: &'static str) -> Package {
    Package::new(directory, Location::Bin)
}

const fn libexec(directory: &'static str) -> Package {
    Package::new(directory, Location::Libexec)
}

const PACKAGES: &[Package] = &[
    bin("adapters/program-std").names(&["gnunet-config"]),
    bin("adapters/config-std").names(&["gnunet-config-diff"]),
    bin("apps/gnunet-abd"),
    bin("apps/gnunet-arm"),
    bin("apps/gnunet-auto-share"),
    bin("apps/gnunet-base32"),
    bin("apps/gnunet-cadet"),
    bin("apps/gnunet-cli").names(&[
        "gnunet-cli",
        "gnunet-did",
        "gnunet-download",
        "gnunet-fs",
        "gnunet-identity",
        "gnunet-namestore",
        "gnunet-namestore-zonefile",
        "gnunet-publish",
        "gnunet-reclaim",
        "gnunet-regex",
        "gnunet-revocation",
        "gnunet-search",
        "gnunet-statistics",
        "gnunet-transport",
        "gnunet-unindex",
        "gnunet-vpn",
    ]),
    bin("apps/gnunet-conversation").names(&["gnunet-conversation", "gnunet-conversation-test"]),
    bin("apps/gnunet-core"),
    bin("apps/gnunet-datastore"),
    bin("apps/gnunet-dht").names(&[
        "gnunet-dht-get",
        "gnunet-dht-hello",
        "gnunet-dht-monitor",
        "gnunet-dht-put",
    ]),
    bin("apps/gnunet-directory"),
    bin("apps/gnunet-dns-monitor"),
    bin("apps/gnunet-dns-redirector"),
    bin("apps/gnunet-ecc"),
    bin("apps/gnunet-gns"),
    bin("apps/gnunet-gns-proxy-setup-ca"),
    bin("apps/gnunet-hello"),
    bin("apps/gnunet-messenger"),
    bin("apps/gnunet-namecache"),
    bin("apps/gnunet-namestore-dbtool"),
    bin("apps/gnunet-nat"),
    bin("apps/gnunet-nat-auto"),
    bin("apps/gnunet-nat-server"),
    bin("apps/gnunet-node"),
    bin("apps/gnunet-nse"),
    bin("apps/gnunet-pils"),
    bin("apps/gnunet-qr"),
    bin("apps/gnunet-resolver"),
    bin("apps/gnunet-rps"),
    bin("apps/gnunet-scalarproduct"),
    bin("apps/gnunet-scrypt"),
    bin("apps/gnunet-testbed").extra(&[
        (
            "gnunet-testing-netjail-launcher",
            Location::Bin,
            Availability::Linux,
        ),
        ("gnunet-cmds-helper", Location::Libexec, Availability::Linux),
    ]),
    bin("apps/gnunet-timeout"),
    bin("apps/gnunet-uri"),
    bin("apps/gnunet-zoneimport"),
    bin("adapters/wfp-dns-std")
        .names(&["gnunet-dns-wfp-control"])
        .features("operator-cli")
        .on(Availability::Windows),
    libexec("adapters/arm-std")
        .names(&["gnunet-arm-spawn-helper"])
        .on(Availability::Unix),
    libexec("apps/gnunet-bcd"),
    libexec("apps/gnunet-communicator-http3"),
    libexec("apps/gnunet-communicator-quic"),
    libexec("apps/gnunet-communicator-tcp"),
    libexec("apps/gnunet-communicator-udp"),
    libexec("apps/gnunet-communicator-unix").on(Availability::Unix),
    libexec("apps/gnunet-daemon-exit"),
    libexec("apps/gnunet-daemon-hostlist"),
    libexec("apps/gnunet-daemon-pt"),
    libexec("apps/gnunet-daemon-regexprofiler"),
    libexec("apps/gnunet-daemon-topology"),
    libexec("apps/gnunet-dns2gns"),
    libexec("apps/gnunet-gns-proxy"),
    libexec("apps/gnunet-helper-audio")
        .names(&["gnunet-helper-audio-playback", "gnunet-helper-audio-record"]),
    libexec("apps/gnunet-helper-dns").on(Availability::Unix),
    libexec("apps/gnunet-helper-exit").on(Availability::Linux),
    libexec("apps/gnunet-helper-nat-client"),
    libexec("apps/gnunet-helper-nat-server"),
    libexec("apps/gnunet-helper-vpn").on(Availability::Linux),
    libexec("apps/gnunet-rest-server").features("oidc"),
    libexec("apps/gnunet-service-abd"),
    libexec("apps/gnunet-service-arm"),
    libexec("apps/gnunet-service-cadet"),
    libexec("apps/gnunet-service-consensus"),
    libexec("apps/gnunet-service-conversation"),
    libexec("apps/gnunet-service-core"),
    libexec("apps/gnunet-service-datastore"),
    libexec("apps/gnunet-service-dht"),
    libexec("apps/gnunet-service-dns"),
    libexec("apps/gnunet-service-fs"),
    libexec("apps/gnunet-service-gns"),
    libexec("apps/gnunet-service-identity"),
    libexec("apps/gnunet-service-messenger"),
    libexec("apps/gnunet-service-namecache"),
    libexec("apps/gnunet-service-namestore"),
    libexec("apps/gnunet-service-nat"),
    libexec("apps/gnunet-service-nat-auto"),
    libexec("apps/gnunet-service-nse"),
    libexec("apps/gnunet-service-peerstore"),
    libexec("apps/gnunet-service-pils"),
    libexec("apps/gnunet-service-reclaim"),
    libexec("apps/gnunet-service-regex"),
    libexec("apps/gnunet-service-resolver"),
    libexec("apps/gnunet-service-revocation"),
    libexec("apps/gnunet-service-rps"),
    libexec("apps/gnunet-service-scalarproduct").names(&[
        "gnunet-service-scalarproduct-alice",
        "gnunet-service-scalarproduct-bob",
        "gnunet-service-scalarproduct-ecc-alice",
        "gnunet-service-scalarproduct-ecc-bob",
    ]),
    libexec("apps/gnunet-service-secretsharing"),
    libexec("apps/gnunet-service-set"),
    libexec("apps/gnunet-service-seti"),
    libexec("apps/gnunet-service-setu"),
    libexec("apps/gnunet-service-statistics"),
    libexec("apps/gnunet-service-transport"),
    libexec("apps/gnunet-service-vpn"),
    libexec("apps/gnunet-service-zonemaster"),
    Package::new("adapters/gns-nss-std", Location::Nss)
        .names(&["nss_gns"])
        .on(Availability::LinuxGnu),
];

pub(super) fn packages(target: &Target) -> impl Iterator<Item = &'static Package> {
    PACKAGES
        .iter()
        .filter(|package| package.platform.supports(target))
}
