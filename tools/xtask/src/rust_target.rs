//! Operating system and toolchain information from Rust target configuration.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OperatingSystem {
    Linux,
    Macos,
    Windows,
    FreeBsd,
    Android,
    Ios,
    OpenHarmony,
}

impl OperatingSystem {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::Macos => "macOS",
            Self::Windows => "Windows",
            Self::FreeBsd => "FreeBSD",
            Self::Android => "Android",
            Self::Ios => "iOS",
            Self::OpenHarmony => "OpenHarmony",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RustTarget {
    pub(super) os: OperatingSystem,
    pub(super) gnu: bool,
}

impl RustTarget {
    pub(super) fn from_cfg(cfg: &str) -> Option<Self> {
        let values = |key: &'static str| cfg.lines().filter_map(move |line| line.strip_prefix(key));
        let mut os = values("target_os=");
        let mut environment = values("target_env=");
        let (os_value, environment_value) = (os.next()?, environment.next());
        if os.next().is_some() || environment.next().is_some() {
            return None;
        }
        let os = match (os_value, environment_value) {
            ("\"linux\"", Some("\"ohos\"")) => OperatingSystem::OpenHarmony,
            ("\"android\"", _) => OperatingSystem::Android,
            ("\"ios\"", _) => OperatingSystem::Ios,
            ("\"linux\"", _) => OperatingSystem::Linux,
            ("\"macos\"", _) => OperatingSystem::Macos,
            ("\"windows\"", _) => OperatingSystem::Windows,
            ("\"freebsd\"", _) => OperatingSystem::FreeBsd,
            _ => return None,
        };
        Some(Self {
            os,
            gnu: environment_value == Some("\"gnu\""),
        })
    }
}
