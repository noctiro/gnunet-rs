//! RFC 3549 message fields shared by Linux UAPI and FreeBSD netlink headers.
//! Native socket addresses, address families and table identifiers stay native.
pub(in crate::routes) const RTM_NEWROUTE: u16 = 24;
pub(in crate::routes) const RTM_DELROUTE: u16 = 25;
pub(in crate::routes) const RTM_GETROUTE: u16 = 26;
pub(in crate::routes) const NLM_F_REQUEST: u16 = 1;
pub(in crate::routes) const NLM_F_MULTI: u16 = 2;
pub(in crate::routes) const NLM_F_ACK: u16 = 4;
pub(in crate::routes) const NLM_F_DUMP_INTR: u16 = 0x10;
pub(in crate::routes) const NLM_F_DUMP: u16 = 0x300;
pub(in crate::routes) const NLM_F_EXCL: u16 = 0x200;
pub(in crate::routes) const NLM_F_CREATE: u16 = 0x400;
pub(in crate::routes) const NLMSG_NOOP: u16 = 1;
pub(in crate::routes) const NLMSG_ERROR: u16 = 2;
pub(in crate::routes) const NLMSG_DONE: u16 = 3;
pub(in crate::routes) const NLMSG_OVERRUN: u16 = 4;
pub(in crate::routes) const RTPROT_STATIC: u8 = 4;
pub(in crate::routes) const RT_SCOPE_UNIVERSE: u8 = 0;
pub(in crate::routes) const RTN_UNICAST: u8 = 1;
pub(in crate::routes) const RTM_F_CLONED: u32 = 0x200;
pub(in crate::routes) const RTA_DST: u16 = 1;
pub(in crate::routes) const RTA_OIF: u16 = 4;
pub(in crate::routes) const RTA_GATEWAY: u16 = 5;
pub(in crate::routes) const RTA_PRIORITY: u16 = 6;
pub(in crate::routes) const RTA_PREFSRC: u16 = 7;
pub(in crate::routes) const RTA_METRICS: u16 = 8;
pub(in crate::routes) const RTA_CACHEINFO: u16 = 12;
pub(in crate::routes) const RTA_TABLE: u16 = 15;
// FreeBSD path metadata. Some values overlap obsolete/different Linux attrs;
// only the FreeBSD parser branch may interpret these native meanings.
pub(in crate::routes) const RTA_KNH_ID: u16 = 10;
pub(in crate::routes) const RTA_WEIGHT: u16 = 13;
pub(in crate::routes) const RTA_RTFLAGS: u16 = 14;
pub(in crate::routes) const RTA_EXPIRES: u16 = 23;
pub(in crate::routes) const RTA_NH_ID: u16 = 30;

#[cfg(target_os = "linux")]
pub(in crate::routes) const DIRECT_SCOPE: u8 = 253; // RT_SCOPE_LINK
#[cfg(target_os = "freebsd")]
pub(in crate::routes) const DIRECT_SCOPE: u8 = RT_SCOPE_UNIVERSE;
#[cfg(target_os = "linux")]
pub(in crate::routes) const DUMP_EVIDENCE: crate::RouteQueryEvidence =
    crate::RouteQueryEvidence::LinuxDump;
#[cfg(target_os = "freebsd")]
pub(in crate::routes) const DUMP_EVIDENCE: crate::RouteQueryEvidence =
    crate::RouteQueryEvidence::FreeBsdDump;
