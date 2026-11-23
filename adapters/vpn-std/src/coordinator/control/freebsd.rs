//! Qualify the original VPN configuration before and after repairing a TUN.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FreeBsdRestore {
    ProbeRoutes(usize),
    ProbeIpv6(LinkRepair),
    Configure { step: u8, repair: LinkRepair },
    ReadBack,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct LinkRepair {
    mtu: bool,
    ipv4: Ipv4Repair,
    ipv6: bool,
    link: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Ipv4Repair {
    Keep,
    AddressAndMask,
    Mask,
}

impl LinkRepair {
    fn before_ipv6(
        prefix: Option<core::Prefix>,
        snapshot: &tun::NativeSnapshot,
        mtu: u32,
    ) -> Result<Self, Fault> {
        use tun::Ipv4Observation::{Absent, Present, Unassigned};
        let ipv4 = if ipv4_matches(prefix, snapshot) {
            Ipv4Repair::Keep
        } else {
            let Some(core::Address::V4(address)) = prefix.map(|p| p.interface) else {
                return Err(Fault::InvalidInput);
            };
            match (snapshot.ipv4_address(), snapshot.ipv4_netmask()) {
                (Absent { .. } | Unassigned, Absent { .. } | Unassigned) => {
                    Ipv4Repair::AddressAndMask
                }
                (Present(current), Absent { .. } | Unassigned) if current.octets() == address => {
                    Ipv4Repair::Mask
                }
                _ => return Err(Fault::Conflict),
            }
        };
        Ok(Self {
            mtu: snapshot.link_mtu() != mtu,
            ipv4,
            ipv6: false,
            link: !snapshot.up(),
        })
    }

    fn requires(self, action: &tun::Action) -> bool {
        match action {
            tun::Action::Mtu(_) => self.mtu,
            tun::Action::Ipv4Address(_) => self.ipv4 == Ipv4Repair::AddressAndMask,
            tun::Action::Ipv4Netmask(_) => self.ipv4 != Ipv4Repair::Keep,
            tun::Action::Ipv6Address { .. } => self.ipv6,
            tun::Action::LinkUp(true) => self.link,
            tun::Action::Route { .. } | tun::Action::LinkUp(false) => false,
        }
    }
}

impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    pub(super) fn poll_freebsd_restore(
        &mut self,
        step: FreeBsdRestore,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        use FreeBsdRestore::{Configure, ProbeIpv6, ProbeRoutes, ReadBack};
        let plan = self.control.plan.ok_or(Fault::NotReady)?;
        match step {
            ProbeRoutes(index @ 0..=1) => {
                if prefix(plan, index).is_some() {
                    self.start_query(index, QueryPurpose::BeforeRestore)?;
                } else {
                    self.control.phase = Phase::Restore(ProbeRoutes(index + 1));
                }
            }
            ProbeRoutes(_) => {
                let snapshot = self.snapshot(plan)?;
                let repair = LinkRepair::before_ipv6(plan.ipv4, &snapshot, self.limits.mtu);
                self.report_snapshot(snapshot, observe);
                if self.stopping.is_some() {
                    return Ok(true);
                }
                match repair {
                    Ok(repair) => {
                        self.control.phase = Phase::Restore(if plan.ipv6.is_some() {
                            ProbeIpv6(repair)
                        } else {
                            Configure { step: 0, repair }
                        });
                    }
                    Err(reason) => self.control_failed(reason, observe)?,
                }
            }
            ProbeIpv6(_) => self.start_dad(plan.ipv6.ok_or(Fault::InvalidInput)?)?,
            Configure { step, repair } if step < MTU_STEPS + 4 => {
                if let Some(action) = native_action(plan, step, self.limits.mtu)?
                    && repair.requires(&action)
                    && !self.apply_control_action(action, observe)?
                {
                    return Ok(true);
                }
                self.control.phase = Phase::Restore(Configure {
                    step: step + 1,
                    repair,
                });
            }
            Configure { .. } => self.control.phase = Phase::Restore(ReadBack),
            ReadBack => {
                let snapshot = self.snapshot(plan)?;
                let ready = snapshot.up()
                    && snapshot.link_mtu() == self.limits.mtu
                    && ipv4_matches(plan.ipv4, &snapshot);
                self.report_snapshot(snapshot, observe);
                if ready {
                    self.control.phase = Phase::Dad;
                } else {
                    self.control_failed(Fault::Conflict, observe)?;
                }
            }
        }
        Ok(true)
    }

    pub(super) fn observe_restore_ipv6(
        &mut self,
        mut repair: LinkRepair,
        observation: tun::Ipv6Observation,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let state = observation.state;
        observe(Event::Ipv6(observation));
        self.stop_watch(observe);
        if self.stopping.is_some() {
            return Ok(());
        }
        repair.ipv6 = match state {
            tun::Ipv6State::Missing => true,
            tun::Ipv6State::Ready | tun::Ipv6State::Tentative | tun::Ipv6State::Detached => false,
            _ => return self.control_failed(Fault::Conflict, observe),
        };
        self.control.phase = Phase::Restore(FreeBsdRestore::Configure { step: 0, repair });
        Ok(())
    }
}
