# Darwin PF state retirement

The [`pf`](src/pf.rs) module retires selected local-source UDP DNS flows through
one original `/dev/pf` descriptor. The DNS helper owns PF rules, delegation,
interface coverage and the recovery journal in the separate
[policy controller](../dns-service-std/PF.md).

## Scope

`DnsStates::select` takes the caller's native assigned-address snapshot, one
absolute `std::time::Instant` and explicit `Limits`. It reads and validates the
complete state table before returning a mutation owner. Selection uses the
original stack-side endpoints, including NAT and NAT64 mappings. It requires a
local source address and UDP destination port 53; IPv6 link-local sources follow
the DNS policy's exclusion. Ordinary incoming replies, remote-origin forwarding,
TCP and other destination ports are outside this scope.

PF direction determines how to recover the original source/destination tuple.
Every native state for a selected local-source DNS flow belongs to the scope,
including equivalent records with different PF directions. Each kill fixes the
address family, both full addresses, both exact ports and the PF interface name.
Selectors are deduplicated while all original state/creator IDs are retained.

Darwin's kill predicate cannot compare state ID or direction. A new state for the
same exact DNS flow may therefore also be removed. The state table lacks socket
group ownership; a matching daemon-group DNS state can be removed too. The
caller excludes concurrent administrative scope changes. This operation grants
no ongoing interface or policy ownership and does not recreate cleared state.

## Native ABI

The boundary uses the 64-bit layouts of `pfioc_states`, `pfioc_state_kill` and
packed `pfsync_state` from Apple's
[`pfvar.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h),
with the predicates and export layout implemented in
[`pf_ioctl.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c).
These are private Darwin interfaces. The implementation guards Darwin releases
20–27; other releases refuse this ABI before opening PF. Packed records are
decoded as bytes without unaligned references, kernel pointer adoption or a
production C dependency.

The kernel's killed-state count occupies an eight-bit field and is not used as
absence proof. `finish` independently reads the complete table and checks every
original selected ID, even if its protocol or endpoints changed.

## Ownership and failure

`retire_next` issues at most one deduplicated selector. The caller may recheck
its policy lease before each call. The owner never reopens PF, extends its
deadline or retries a failed mutation. Errors retain the original cause and
attempted/completed command counts; these counts do not assert how many states
were deleted. `finish` consumes the owner and refuses unfinished or failed work.
Drop closes the original descriptor without further mutation or rollback.

The same deadline covers table acquisition, allocation, selection, every kill
and complete-table readback. Synchronous kernel calls retain their original
buffers until return and cannot be interrupted through this API. Late completion
is an error even when the kernel has already removed state.

## Resource bounds

Defaults permit 65,536 native state rows and 4096 selected state identities.
The table buffer grows from the actual native size probe and is reused for
readback. An extra 297-byte row distinguishes a complete snapshot from a full
buffer prefix. Default table payload is bounded to `(65,536 + 1) × 297` bytes;
identity and selector vectors are bounded independently by the selected-state
limit. Oversized, malformed or incomplete snapshots and duplicate selected
identities refuse admission. An overestimated native size probe can still
qualify through a complete bounded read.

## Example

```rust,no_run
use gnunet_native::pf::{DnsStates, Limits};
use std::time::{Duration, Instant};

fn retire(local: &[std::net::IpAddr]) -> std::io::Result<()> {
    let until = Instant::now() + Duration::from_secs(10);
    let mut states = DnsStates::select(local, until, Limits::default())?;
    while states.retire_next()? {}
    states.finish()
}
```
