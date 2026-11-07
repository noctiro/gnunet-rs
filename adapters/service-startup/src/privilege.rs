//! Exact native GNUnet gid/group/uid short-circuit and fallback sequence.
use gnunet_config::{Configuration, ProcessEnvironment};
use nix::unistd::{self, Gid, Uid};
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fmt, io,
    os::unix::ffi::OsStrExt,
};
/// Selected original compile-time initgroups capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupsProfile {
    /// Matches the current unchanged normal C HAVE_INITGROUPS=1 profile.
    WithInitgroups,
    /// Explicit alternate conditional branch; no implicit groups reset claim.
    WithoutInitgroups,
}
/// Infallible actual process identity reads; no supplementary/saved-id promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Real UID.
    pub uid: u32,
    /// Effective UID.
    pub euid: u32,
    /// Real GID.
    pub gid: u32,
    /// Effective GID.
    pub egid: u32,
}
impl Identity {
    /// Read the calling process's actual IDs through safe OS wrappers.
    pub fn current() -> Self {
        Self {
            uid: unistd::getuid().as_raw(),
            euid: unistd::geteuid().as_raw(),
            gid: unistd::getgid().as_raw(),
            egid: unistd::getegid().as_raw(),
        }
    }
}
/// Native syscall position, used only for truthful local failure diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeStage {
    /// Primary setgid.
    SetGid,
    /// Primary setegid.
    SetEffectiveGid,
    /// Conditional primary initgroups.
    InitGroups,
    /// Primary setuid.
    SetUid,
    /// Primary seteuid.
    SetEffectiveUid,
    /// Fallback setregid(gid,gid).
    SetBothGid,
    /// Fallback setreuid(uid,uid).
    SetBothUid,
}
/// What actually succeeded, including the original permissive fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeRoute {
    /// No configured user; no identity mutation was attempted.
    Unchanged,
    /// All enabled primary operations returned success.
    Primary,
    /// Primary stopped at one failure and both fallback calls returned success.
    Fallback {
        /// First failed primary syscall; later primary calls were not made.
        failed_stage: PrivilegeStage,
        /// Actual original errno, if provided by the OS boundary.
        raw_os_error: Option<i32>,
    },
}
/// Actual local sequence outcome, not a stronger saved-id/capability guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegeReport {
    /// Actual IDs immediately before this attempt.
    pub before: Identity,
    /// Actual IDs after the completed sequence.
    pub after: Identity,
    /// Exact primary/fallback/no-op route.
    pub route: PrivilegeRoute,
    /// Whether initgroups actually returned success in this invocation.
    pub groups_initialized: bool,
    /// Explicit source conditional profile.
    pub profile: GroupsProfile,
}
/// Unsuccessful lookup or syscall, with partial identity changes kept visible.
#[derive(Debug)]
pub enum PrivilegeError {
    /// Caller bytes cannot be represented as a native CString account name.
    InvalidName,
    /// Native reentrant lookup returned no account or a lookup failure. uzers
    /// does not distinguish these reliably, so no fabricated errno is attached.
    AccountUnavailable {
        /// Original opaque Unix account bytes.
        name: OsString,
    },
    /// The native fallback failed. Startup must exit; rollback is not attempted.
    Apply {
        /// Failing fallback operation.
        stage: PrivilegeStage,
        /// Actual OS error.
        error: io::Error,
        /// The primary operation that first failed.
        primary_stage: PrivilegeStage,
        /// Actual first primary errno, if present.
        primary_raw_os_error: Option<i32>,
        /// IDs before any attempt.
        before: Identity,
        /// Actual possibly partially changed IDs at refusal.
        after: Identity,
    },
}
impl fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("USERNAME contains NUL"),
            Self::AccountUnavailable { .. } => {
                f.write_str("native USERNAME account lookup unavailable")
            }
            Self::Apply { stage, error, .. } => {
                write!(f, "native privilege operation {stage:?}: {error}")
            }
        }
    }
}
impl std::error::Error for PrivilegeError {}
/// Resolved native account identity, retaining the original raw name for initgroups.
#[derive(Debug)]
pub struct PrivilegePlan {
    name: OsString,
    cname: CString,
    uid: u32,
    gid: u32,
}
impl PrivilegePlan {
    /// Original opaque name; this is not filename-expanded again.
    pub fn name(&self) -> &OsStr {
        &self.name
    }
    /// UID actually returned by native account lookup.
    pub fn uid(&self) -> u32 {
        self.uid
    }
    /// Primary GID actually returned by native account lookup.
    pub fn gid(&self) -> u32 {
        self.gid
    }
}
/// Preserve USERNAME's original filename/dollar expansion. Missing means keep
/// identity; invalid present configuration is an explicit fail-closed error.
pub fn configured_user(
    config: &Configuration,
    section: &[u8],
) -> Result<Option<OsString>, gnunet_config::Error> {
    config
        .get(section, b"USERNAME")
        .map(|_| {
            config
                .get_filename(section, b"USERNAME", &ProcessEnvironment)
                .map(|p| p.into_os_string())
        })
        .transpose()
}
/// Resolve opaque account bytes through a maintained safe native wrapper.
/// This can consult the configured account NSS service; it never changes an
/// account or invokes the resolver's DNS/NSS convenience APIs.
pub fn resolve_user(name: &OsStr) -> Result<PrivilegePlan, PrivilegeError> {
    let cname = CString::new(name.as_bytes()).map_err(|_| PrivilegeError::InvalidName)?;
    let user = uzers::get_user_by_name(name).ok_or_else(|| PrivilegeError::AccountUnavailable {
        name: name.to_owned(),
    })?;
    Ok(PrivilegePlan {
        name: name.to_owned(),
        cname,
        uid: user.uid(),
        gid: user.primary_group_id(),
    })
}
trait Operations {
    fn set_gid(&mut self, gid: u32) -> io::Result<()>;
    fn set_egid(&mut self, gid: u32) -> io::Result<()>;
    fn init_groups(&mut self, name: &CStr, gid: u32) -> io::Result<()>;
    fn set_uid(&mut self, uid: u32) -> io::Result<()>;
    fn set_euid(&mut self, uid: u32) -> io::Result<()>;
    fn both_gid(&mut self, gid: u32) -> io::Result<()>;
    fn both_uid(&mut self, uid: u32) -> io::Result<()>;
}
struct Native;
impl Operations for Native {
    fn set_gid(&mut self, gid: u32) -> io::Result<()> {
        unistd::setgid(Gid::from_raw(gid)).map_err(io::Error::from)
    }
    fn set_egid(&mut self, gid: u32) -> io::Result<()> {
        unistd::setegid(Gid::from_raw(gid)).map_err(io::Error::from)
    }
    fn init_groups(&mut self, name: &CStr, gid: u32) -> io::Result<()> {
        init_groups(name, gid)
    }
    fn set_uid(&mut self, uid: u32) -> io::Result<()> {
        unistd::setuid(Uid::from_raw(uid)).map_err(io::Error::from)
    }
    fn set_euid(&mut self, uid: u32) -> io::Result<()> {
        unistd::seteuid(Uid::from_raw(uid)).map_err(io::Error::from)
    }
    fn both_gid(&mut self, gid: u32) -> io::Result<()> {
        uzers::switch::set_both_gid(gid, gid)
    }
    fn both_uid(&mut self, uid: u32) -> io::Result<()> {
        uzers::switch::set_both_uid(uid, uid)
    }
}
#[cfg(not(target_os = "macos"))]
fn init_groups(name: &CStr, gid: u32) -> io::Result<()> {
    unistd::initgroups(name, Gid::from_raw(gid)).map_err(io::Error::from)
}
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "nix omits Darwin initgroups; the platform libc ABI consumes a live terminated CStr and an integer gid with no retained pointers"
)]
fn init_groups(name: &CStr, gid: u32) -> io::Result<()> {
    // SAFETY: name remains a live NUL-terminated CString for the complete call.
    // Darwin's public initgroups ABI takes c_int basegroup, exactly as the C
    // source's implicit pw_gid conversion; no Rust memory is written or retained.
    let result = unsafe { libc::initgroups(name.as_ptr(), gid as libc::c_int) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn primary(
    ops: &mut impl Operations,
    p: &PrivilegePlan,
    profile: GroupsProfile,
    initialized: &mut bool,
) -> Result<(), (PrivilegeStage, io::Error)> {
    ops.set_gid(p.gid)
        .map_err(|e| (PrivilegeStage::SetGid, e))?;
    ops.set_egid(p.gid)
        .map_err(|e| (PrivilegeStage::SetEffectiveGid, e))?;
    if profile == GroupsProfile::WithInitgroups {
        ops.init_groups(&p.cname, p.gid)
            .map_err(|e| (PrivilegeStage::InitGroups, e))?;
        *initialized = true;
    }
    ops.set_uid(p.uid)
        .map_err(|e| (PrivilegeStage::SetUid, e))?;
    ops.set_euid(p.uid)
        .map_err(|e| (PrivilegeStage::SetEffectiveUid, e))?;
    Ok(())
}
struct SequenceError {
    stage: PrivilegeStage,
    error: io::Error,
    primary_stage: PrivilegeStage,
    primary_raw_os_error: Option<i32>,
}
fn sequence(
    ops: &mut impl Operations,
    p: &PrivilegePlan,
    profile: GroupsProfile,
) -> Result<(PrivilegeRoute, bool), SequenceError> {
    let mut initialized = false;
    match primary(ops, p, profile, &mut initialized) {
        Ok(()) => Ok((PrivilegeRoute::Primary, initialized)),
        Err((primary_stage, error)) => {
            let errno = error.raw_os_error();
            ops.both_gid(p.gid).map_err(|error| SequenceError {
                stage: PrivilegeStage::SetBothGid,
                error,
                primary_stage,
                primary_raw_os_error: errno,
            })?;
            ops.both_uid(p.uid).map_err(|error| SequenceError {
                stage: PrivilegeStage::SetBothUid,
                error,
                primary_stage,
                primary_raw_os_error: errno,
            })?;
            Ok((
                PrivilegeRoute::Fallback {
                    failed_stage: primary_stage,
                    raw_os_error: errno,
                },
                initialized,
            ))
        }
    }
}
/// Apply the exact C native sequence to this process only. Call from startup in
/// a fresh service process before unrelated threads/tasks and account-dependent
/// operations. It is irreversible: on error identity may already be partially
/// changed, and the caller must exit rather than continue or roll back. Successful
/// fallback does not assert supplementary-group or saved-privilege removal.
pub fn apply_privileges(
    plan: Option<&PrivilegePlan>,
    profile: GroupsProfile,
) -> Result<PrivilegeReport, PrivilegeError> {
    let before = Identity::current();
    let Some(plan) = plan else {
        return Ok(PrivilegeReport {
            before,
            after: before,
            route: PrivilegeRoute::Unchanged,
            groups_initialized: false,
            profile,
        });
    };
    match sequence(&mut Native, plan, profile) {
        Ok((route, initialized)) => Ok(PrivilegeReport {
            before,
            after: Identity::current(),
            route,
            groups_initialized: initialized,
            profile,
        }),
        Err(SequenceError {
            stage,
            error,
            primary_stage,
            primary_raw_os_error,
        }) => Err(PrivilegeError::Apply {
            stage,
            error,
            primary_stage,
            primary_raw_os_error,
            before,
            after: Identity::current(),
        }),
    }
}
#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic,
        reason = "Pure component tests fail explicitly when the original C sequence selects the wrong branch"
    )]
    #![expect(
        clippy::unwrap_used,
        reason = "Pure deterministic component fixtures unwrap only fixed valid local test values"
    )]
    use super::*;
    struct Model {
        calls: Vec<PrivilegeStage>,
        fail: Vec<PrivilegeStage>,
    }
    impl Model {
        fn call(&mut self, stage: PrivilegeStage) -> io::Result<()> {
            self.calls.push(stage);
            if self.fail.contains(&stage) {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        }
    }
    impl Operations for Model {
        fn set_gid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetGid)
        }
        fn set_egid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetEffectiveGid)
        }
        fn init_groups(&mut self, _: &CStr, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::InitGroups)
        }
        fn set_uid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetUid)
        }
        fn set_euid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetEffectiveUid)
        }
        fn both_gid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetBothGid)
        }
        fn both_uid(&mut self, _: u32) -> io::Result<()> {
            self.call(PrivilegeStage::SetBothUid)
        }
    }
    fn plan() -> PrivilegePlan {
        PrivilegePlan {
            name: OsString::from("fixture"),
            cname: CString::new("fixture").unwrap(),
            uid: 123,
            gid: 456,
        }
    }
    fn primary_stages(profile: GroupsProfile) -> Vec<PrivilegeStage> {
        let mut p = vec![PrivilegeStage::SetGid, PrivilegeStage::SetEffectiveGid];
        if profile == GroupsProfile::WithInitgroups {
            p.push(PrivilegeStage::InitGroups)
        }
        p.extend([PrivilegeStage::SetUid, PrivilegeStage::SetEffectiveUid]);
        p
    }
    #[test]
    fn original_primary_short_circuit_and_every_fallback_failure_position() {
        // Component-only injected errno/order evidence. No native identity call.
        for profile in [
            GroupsProfile::WithInitgroups,
            GroupsProfile::WithoutInitgroups,
        ] {
            let p = primary_stages(profile);
            for failed in 0..p.len() {
                for fallback_failure in [
                    None,
                    Some(PrivilegeStage::SetBothGid),
                    Some(PrivilegeStage::SetBothUid),
                ] {
                    let mut m = Model {
                        calls: Vec::new(),
                        fail: vec![p[failed]],
                    };
                    if let Some(f) = fallback_failure {
                        m.fail.push(f)
                    }
                    let result = sequence(&mut m, &plan(), profile);
                    let mut expected = p[..=failed].to_vec();
                    expected.push(PrivilegeStage::SetBothGid);
                    if fallback_failure != Some(PrivilegeStage::SetBothGid) {
                        expected.push(PrivilegeStage::SetBothUid)
                    }
                    assert_eq!(m.calls, expected);
                    match (result, fallback_failure) {
                        (
                            Ok((
                                PrivilegeRoute::Fallback {
                                    failed_stage,
                                    raw_os_error,
                                },
                                initialized,
                            )),
                            None,
                        ) => {
                            assert_eq!(failed_stage, p[failed]);
                            assert_eq!(raw_os_error, Some(libc::EPERM));
                            assert_eq!(
                                initialized,
                                profile == GroupsProfile::WithInitgroups && failed > 2
                            );
                        }
                        (Err(e), Some(stage)) => {
                            assert_eq!(e.stage, stage);
                            assert_eq!(e.primary_stage, p[failed]);
                            assert_eq!(e.primary_raw_os_error, Some(libc::EPERM));
                        }
                        _ => panic!("wrong original short-circuit route"),
                    }
                }
            }
        }
    }
    #[test]
    fn original_primary_success_conditional_groups_and_raw_name_do_not_normalize() {
        for profile in [
            GroupsProfile::WithInitgroups,
            GroupsProfile::WithoutInitgroups,
        ] {
            let mut m = Model {
                calls: Vec::new(),
                fail: Vec::new(),
            };
            let result = sequence(&mut m, &plan(), profile).ok().unwrap();
            assert_eq!(m.calls, primary_stages(profile));
            assert_eq!(
                result,
                (
                    PrivilegeRoute::Primary,
                    profile == GroupsProfile::WithInitgroups
                )
            );
        }
        assert!(matches!(
            resolve_user(OsStr::from_bytes(b"a\0b")),
            Err(PrivilegeError::InvalidName)
        ));
    }
}
