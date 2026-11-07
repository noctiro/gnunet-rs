# gnunet-tun-helper-host

Dedicated, single-threaded Linux helper implementation shared by the installed
`gnunet-helper-vpn` and `gnunet-helper-exit` binaries. It links only the existing
libc, small native boundary and pure wire/types, without a service, async runtime,
cryptography or libgnunet FFI. Public entry points are `run(Profile)`, `diagnostic`
and the owned `Failure` exit-code getter; this is not an embedded service API.

VPN keeps its five positional arguments: `tun ipv6|- prefix ipv4|- mask`. EXIT uses six: `tun egress|- ipv6|- prefix ipv4|- mask`. Enabled IPv6 permits
prefix1..127; disabled families ignore the associated prefix/mask. EXIT refuses
both families disabled. Interface arguments preserve OS bytes and are bounded by
IFNAMSIZ; EXIT egress denotes one literal interface, not an iptables '+' wildcard. There are no PROGRAM options, READY bytes, private messages or helper ACKs.

For EXIT with an egress, successful `sysctl -w` enables forwarding for each
selected family. IPv4 additionally requires exit0 from `iptables -t nat
-A POSTROUTING -o EGRESS -j MASQUERADE`. Tools are selected only from the fixed
root-owned executable paths `/sbin` and `/usr/sbin`, with no shell or PATH lookup. A fresh controlled environment, null stdin and private stdout/stderr pipes keep
all command output out of the type185 channel. Each stream retains at most4096
bytes while draining excess; its total and status/errors are diagnostic. No rc1 or output string means rule absence, no existing rule is deleted, and no
presence test is treated as proof. Repeated starts can append another rule.

Each command has one native30s target captured before spawn. Polling fairly
checks the original child, both capture pipes, signal/parent lifetime and that
same target. Error/stop/timeout kills an unreaped original child and waits for
that same Child; an wait error remains an error, not a reap receipt. SIGCHLD is set to a waitable policy and restored after original waits. The child
also arms Linux parent-death SIGKILL and rechecks its helper parent before exec. Synchronous OS spawn/kill/wait can still block; the target cannot forcibly cancel
an uninterruptible OS operation. There is no detached waiter or claimed join.

Required EXIT operations finish before the fresh TUN can become observable as
ready. Unlike pinned C's warning-and-continue behavior, failure is terminal and
retains status/errno plus independent close/restoration errors. Following
C, global forwarding settings and appended NAT rules are NOT rolled back on
stop, partial setup failure or later TUN failure. Their ownership is not invented. A parent observes kernel/interface/route/DAD facts independently; process
creation, local exit0 and sysctl/iptables status are not remote reachability ACKs.

The shared TUN implementation is extracted from Root2638's compiled VPN source:
fresh IFF_TUN|IFF_TUN_EXCL with PI retained, address/netmask/UP ioctls,
optional explicit MTU, original typed FD ownership and single-close errors. The default MTU is never changed/guessed. Only an existing
`GNUNET_VPN_HELPER_MTU` selects the bounded Rust-only override for either helper;
the original C helpers do not read it. Maximum raw packet65527 fits the NBO16
frame with header4+PI4; IPv6 requires MTU>=1280.

The same signal owner spans setup, permanent real-ID/group/capability drop and
packet pumping so a setup stop is never reset. Handlers only store the stop flag;
all configuration and privileged child waits precede the drop, and every
error path attempts the drop before terminal diagnostics. Real UID0 remains0. Original parent-death watch is armed after reduction. No secrets or packet bytes
are printed. Diagnostic output is bounded and best effort on fd2.

Original type185 framing is header4+PI4+IP in both directions. Two reused buffers
(about128KiB) preserve partial stream cursors; one complete TUN datagram uses one
write and a short write fails instead of splitting its tail into another packet. Oversize/PIstrip and 16bit-overflow input are rejected. Each pending packet
keeps its first-positive native30s target; true idle has no overall deadline. Signal/parent/native targets are checked before each round-robin IO class. Inherited stdin/stdout OFD flags are never changed. Regular-file/terminal calls
have an explicit synchronous OS blocking boundary, not hard preemption.
