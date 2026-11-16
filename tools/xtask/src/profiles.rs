//! Independent production feature selections shared by every native CI host.

enum Target {
    Library,
    Binary(&'static str),
}

struct BuildProfile {
    package: &'static str,
    features: &'static str,
    target: Target,
}

impl BuildProfile {
    const fn library(package: &'static str, features: &'static str) -> Self {
        Self {
            package,
            features,
            target: Target::Library,
        }
    }

    const fn binary(package: &'static str, binary: &'static str, features: &'static str) -> Self {
        Self {
            package,
            features,
            target: Target::Binary(binary),
        }
    }

    fn command(&self) -> Vec<&'static str> {
        let mut command = vec![
            "cargo",
            "check",
            "--locked",
            "-p",
            self.package,
            "--no-default-features",
        ];
        if !self.features.is_empty() {
            command.extend(["--features", self.features]);
        }
        match self.target {
            Target::Library => command.push("--lib"),
            Target::Binary(binary) => command.extend(["--bin", binary]),
        }
        command
    }
}

// Separate Cargo invocations keep other workspace packages and development
// dependencies from supplying a missing production feature.
const PROFILES: &[BuildProfile] = &[
    BuildProfile::library("gnunet-program-host", "service-runtime"),
    BuildProfile::library("gnunet-program-host", "binary-io"),
    BuildProfile::library("gnunet-fs-host", "extraction"),
    BuildProfile::library("gnunet-fs-host", "service"),
    BuildProfile::library("gnunet-fs-host", "server"),
    BuildProfile::library("gnunet-quic-communicator-host", "program"),
    BuildProfile::library("gnunet-quic-communicator-host", "program,h3-profile"),
    BuildProfile::library("gnunet-gns-proxy-host", ""),
    BuildProfile::library("gnunet-dns2gns-host", ""),
    BuildProfile::library("gnunet-pils-host", "service"),
    BuildProfile::binary("gnunet-transport-node", "gnunet-transport-node", ""),
    BuildProfile::library("gnunet", "official-dht-client"),
    BuildProfile::library("gnunet", "official-gns-client"),
    BuildProfile::library("gnunet", "official-fs-extraction"),
    BuildProfile::binary("gnunet-cli", "gnunet-cli", "fs"),
];

pub(crate) fn commands() -> Vec<Vec<&'static str>> {
    PROFILES.iter().map(BuildProfile::command).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_checks_cannot_unify_other_packages_or_development_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        for command in commands() {
            if command.windows(2).filter(|pair| pair[0] == "-p").count() != 1
                || !command.contains(&"--no-default-features")
                || !command.contains(&"--locked")
                || [
                    "--workspace",
                    "--all-targets",
                    "--tests",
                    "--examples",
                    "--all-features",
                ]
                .iter()
                .any(|flag| command.contains(flag))
                || command.contains(&"--lib") == command.contains(&"--bin")
                || command
                    .windows(2)
                    .any(|pair| pair[0] == "--features" && pair[1].is_empty())
            {
                return Err(format!("production profile lost isolation: {command:?}").into());
            }
        }
        let facade: Vec<_> = commands()
            .into_iter()
            .filter(|command| command.windows(2).any(|pair| pair == ["-p", "gnunet"]))
            .collect();
        if facade.iter().any(|command| {
            command
                .windows(2)
                .any(|pair| pair[0] == "--features" && pair[1].contains(','))
        }) {
            return Err("independent SDK entry points were unified into one profile".into());
        }
        Ok(())
    }
}
