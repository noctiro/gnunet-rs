//! Restrictive replacement decisions over OS-validated same-team properties.
use std::{fmt, io, str::FromStr};

/// Three numeric CFBundleVersion components accepted by the bundle helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version([u32; 3]);
impl Version {
    /// Preserve the exact three numeric bundle version components.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self([major, minor, patch])
    }
}
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}
impl FromStr for Version {
    type Err = io::Error;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut parts = text.split('.');
        let mut components = [0; 3];
        for component in &mut components {
            let part = parts.next().ok_or_else(invalid_version)?;
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid_version());
            }
            *component = part.parse().map_err(|_| invalid_version())?;
        }
        if parts.next().is_some() {
            return Err(invalid_version());
        }
        Ok(Self(components))
    }
}
fn invalid_version() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "expected three numeric bundle version components",
    )
}

/// Explicit activation conflict policy; arbitrary replacement is never implicit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplacementPolicy {
    /// Refuse an installed extension conflict, including developer-mode repeats.
    #[default]
    Reject,
    /// Replace only an older same-bundle/team extension with this exact version.
    /// Both proposed bundle version strings must equal this numeric version.
    UpgradeTo(Version),
}
/// Original local disposition returned to the native replacement delegate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacementDecision {
    /// Explicit policy accepted a strictly newer exact proposed version.
    Upgrade,
    /// No replacement was authorized.
    RejectedByPolicy,
    /// At least one property bundle ID differs from the original request.
    BundleIdentityMismatch,
    /// A native version string is malformed or exceeds the bounded conversion.
    InvalidVersion,
    /// The proposal differs from the explicit target version.
    UnexpectedProposedVersion,
    /// The existing bundle is equal/newer or its short version would downgrade.
    NotAnUpgrade,
}
impl ReplacementPolicy {
    pub(super) fn decide(
        self,
        same_bundle: bool,
        versions: Option<[Version; 4]>,
    ) -> ReplacementDecision {
        let Self::UpgradeTo(expected) = self else {
            return ReplacementDecision::RejectedByPolicy;
        };
        if !same_bundle {
            return ReplacementDecision::BundleIdentityMismatch;
        }
        let Some([old, old_short, new, new_short]) = versions else {
            return ReplacementDecision::InvalidVersion;
        };
        if new != expected || new_short != expected {
            return ReplacementDecision::UnexpectedProposedVersion;
        }
        if old >= expected || old_short > expected {
            return ReplacementDecision::NotAnUpgrade;
        }
        ReplacementDecision::Upgrade
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplacementDecision as D, ReplacementPolicy as P, Version as V};
    #[test]
    fn upgrade_policy_never_accepts_arbitrary_identity_or_version() {
        let old = V::new(1, 0, 0);
        let target = V::new(2, 0, 0);
        let newer = V::new(3, 0, 0);
        let exact = Some([old, old, target, target]);
        assert_eq!(P::Reject.decide(true, exact), D::RejectedByPolicy);
        assert_eq!(
            P::UpgradeTo(target).decide(false, exact),
            D::BundleIdentityMismatch
        );
        assert_eq!(P::UpgradeTo(target).decide(true, None), D::InvalidVersion);
        assert_eq!(
            P::UpgradeTo(target).decide(true, Some([old, old, newer, newer])),
            D::UnexpectedProposedVersion
        );
        assert_eq!(
            P::UpgradeTo(target).decide(true, Some([target, target, target, target])),
            D::NotAnUpgrade
        );
        assert_eq!(
            P::UpgradeTo(target).decide(true, Some([old, newer, target, target])),
            D::NotAnUpgrade
        );
        assert_eq!(P::UpgradeTo(target).decide(true, exact), D::Upgrade);
        assert!("1.0".parse::<V>().is_err());
        assert!("1.0.0.1".parse::<V>().is_err());
    }
}
