# GNUnet NAT test caller and command-line API (N4)

caller-polled production implementation over gnunet-nat-client-host, the shared generic CLIENT/framing/Resolver/clock, and N2/N3 NAT network ports.

## finite test caller

`Test::start(instance, Sources, Request, Limits)` binds a TCP listener/UDP socket before registering that local endpoint. `Test::from_configuration` reads the official adapter section PORT/protocol and freezes NAT +gnunet-nat-server endpoints coherently. Constructors establish owners and socket binding; they do not claim reachability. The caller drives the existing shared Resolver broker and `Test::poll`/`drive`.

Each IPv4 address-add callback opens a dedicated original test-server MQ, encodes the official16-byte NAT_TEST and tracks partial/whole write bytes. There is no RID, ACK, cancellation frame or mutation replay. A zero service-advertised port in normal TCP/UDP testing uses the bound local port as the attempted target, without claiming this is an observed mapped port. IPv6 address hints remain valid in Registration but are not converted to an invented IPv6 test frame: the active official test wire is IPv4-only.

Every original address allocation/epoch gets a different public two-byte challenge, with bounded non-reused tombstones for removed addresses. A success observation requires the dedicated request's full local write, the original UDP/TCP listener or NAT reversal callback, exact challenge match, the same live registration epoch and still-current AddressId. A late old-address callback cannot be relabeled as a new target. TCP preserves partial two-byte reads and per-accepted-stream original native deadlines; oversized UDP challenge payloads are rejected by the3-byte receive sentinel. Source, target, stream, datagram-work and deadline bounds are explicit. No local send, EOF, timeout, allocation success or address hint creates a received observation.

The two-byte challenge and ICMP reversal are unauthenticated. `Observation` is sealed metadata of an matched network-path observation, not a peer identity or cryptographic proof. Outcomes distinguish Received/Timeout/Cancelled/failure. Terminal address/callback and per-target byte-exposure owners are transferred; terminal metadata is pre-reserved before native work rather than allocated after physical close. Explicit cancel/drop physically stops original MQs/listeners/streams and never pretends to undo an already-admitted remote test action.

For official PORT0 reversal testing, Rust owns a ephemeral binding of the requested TCP/UDP protocol and registers its wildcard endpoint. Reversal-mode success only consumes the NAT callback; an unrelated TCP/UDP listener response cannot be relabeled as ICMP traversal. The pinned C test registers no bindings (so its service does not consider it NATed) and leaves its challenge zero (its raw helper rejects port0). Rust sends the unchanged official dport0 test format with a valid nonzero per-target challenge/advertised port, then consumes the original reverse callback. No private malformed fallback or fake binding is used. A corrected Rust service and ordinary official NAT service can recognize the natted registration flags; this does not force a defective official helper/daemon to succeed.

All original absolute and native targets remain fixed. Native hard/input/target alarms and physical expiration run before canonical clock stabilization; normal clock rollback never refreshes old work. Incoming data cannot bind to a target lacking an whole request write. Source loss retires old address/callback authority. Dropping a borrowed waiting future retains original partial cursors; it does not create a new epoch.

## commands

`gnunet-nat` uses standard --in/-i, --remote/-r, --section/-S, --stun/-s, --tcp/-t, --udp/-u and --watch/-W plus shared PROGRAM defaults. It uses the native Registration, never another registration MQ implementation. STUN binds a supplied UDP endpoint, uses original transactions on that same socket, receives whole datagrams in a bounded65536-byte owner, and forwards only matching current-epoch responses. Original reversal intent is one-shot, retains its initial deadline across reconnect, and is not replayed. Every queued higher-level write also retains its original independent native bound; expiration removes only unexposed writes or physically closes an exposed original MQ, using the native client's cancellation receipt. Ongoing monitoring explicitly creates fresh finite registration leases; old app-context/address owners and one-shot writes are not rebound. A clock/process-port refusal stops the owner instead of silently replacing the clock or recovering a refused port.

`gnunet-nat-auto` uses standard --auto/-a, --section/-S, --tcp/-t, --udp/-u and --write/-w plus shared PROGRAM defaults. It executes AutoQuery and/or the test caller. It preserves raw status/type (including type0); proposals are not connectivity evidence. Only a successful config response can be applied, and only proposed NAT section values are published when --write was requested. It uses the shared configuration write_diffs port and selected original filename; no file publication/daemon activation is claimed before that call succeeds. The test uses the original running service/config snapshot; writing a proposal does not secretly reconfigure a running daemon.

Both commands share one PROGRAM task, canonical clock and explicitly driven official Resolver broker. Original action sockets/providers are dropped before Resolver cleanup, and independent errors remain visible. Signal cancellation is local, no fake GNUNET success status. PROGRAM's GNUNET_OK1 is separate from process exit0. TCP and UDP are mutually exclusive. An absent action or unexpected closure without an result is an error rather than a no-op success.

## Interfaces and limits

The SDK exports `clients::nat_test` separately from `clients::nat`, which
provides registration and automatic-configuration queries.

The public util burst API is supplied separately by gnunet-nat-burst-host. Current production helper entry points include Linux, Darwin and modern FreeBSD, and the shared IGD transport supports HTTP and verified HTTPS. Other helper targets remain explicit capability refusals. These existing source paths supersede the earlier N3 Linux-only/HTTPS limitations; no complete official-C interoperability, packet checksum/crypto runtime or system integration acceptance is claimed here.

No Cargo/compiler/model/test/native/socket/network/helper/process/permission/route/storage/configuration-write/entropy/cryptography/key execution. No existing or newly generated private key was read or hashed; no stopped GNS/DHT/UDP owner or directory was accessed.
