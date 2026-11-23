# Windows WFP DNS adapter

`gnunet-wfp-dns-host` provisions persistent callout metadata and owns the
service's local DNS device channel. The [kernel driver](../../platform/windows/wfp-driver/README.md)
owns discovery, capture and receive-guard filters, packet storage and native
injection. The [DNS backend contract](../dns-service-std/NATIVE_BACKENDS.md)
defines service integration and shutdown ownership.

## Static metadata

Generate an `InstallationReceipt` and persist its nonce before changing BFE.
Open `Provisioner` with `ProvisionLimits` and give it that receipt to install
the canonical persistent provider and six callouts in one native transaction.
The calling token needs the native metadata rights. The driver owns the capture
filters and the separate service lifecycle.

After an uncertain install result, `verify` inspects all seven objects under a
native read-only transaction using the same receipt. Removal verifies all
original keys, providers, layers, flags and nonce bindings in its write
transaction before deleting any record. Numeric callout IDs can change across
BFE restarts. Installation refuses collisions with existing keys.

`ProvisionLimits::transaction_wait` bounds transaction-lock acquisition, not
RPC completion. Failures preserve the original operation, independent abort
result and commit uncertainty. Explicit `close` observes engine retirement;
neither failed close nor cleanup is retried, and Drop changes no BFE policy.

## Operator commands

Build `gnunet-dns-wfp-control` with the `operator-cli` feature on Windows.
Use the native x64 or ARM64 command on Windows build 19041 or newer.
`verify-driver-package DIR` opens the fixed INF, SYS and catalog from a local
package directory. Windows verifies the INF and SYS as members of that SHA-256
catalog using its driver trust policy and cached certificate-chain data.
`install-driver DIR` keeps those files open and invokes the primitive driver
installer using its default selection policy. It refuses an existing
`GNUnetDnsIntercept` service. Windows may report `RestartRequired` with
exit 3. This command leaves the restart under operator control.

Use `inspect-driver DIR` after restart or an interrupted installation. It
matches the SCM image path and published INF to the exact source package in
the Driver Store, then prints the observed SCM state and published INF path.
Run one privileged deployment or SCM configuration operation at a time.
Keep the verified package for later inspection and startup.

`prepare-policy` prints the receipt as 64 hexadecimal digits. Save it before
`install-policy RECEIPT`. Use `verify-policy RECEIPT` to check an interrupted
installation and `remove-policy RECEIPT` for verified removal.
`start-driver DIR RECEIPT` requires the exact installed package and verifies
the original WFP metadata receipt before asking SCM to start the service.
Exit 3 means SCM still reports `StartPending`. `AlreadyRunning` reports
SCM's pre-existing running state. Start the GNUnet DNS data service after
SCM reports the driver running.

After stopping the DNS data service, use `stop-driver DIR` with the verified
package. Each invocation advances native rundown and can enter the passive
native wait. If a previous invocation completed handoff before exiting, the
command recovers the terminal result through a read-only handle to the
still-loaded driver. SCM stop requires a verified terminal response and
successful closure of the handle that observed it. Exit 3 reports pending
native rundown, start or stop. Repeat the command to advance an open rundown
or observe the pending SCM state. Exit 0 reports SCM `Stopped` and both exit
values.

Use `remove-driver DIR` after SCM reports `Stopped`. `DIR` must be a separate
signed copy of the installed package. Windows removes the matching published
OEM INF and its Driver Store package through the primitive driver uninstall
operation. `Removed` and exit 0 confirm absence of the original paths and SCM
entry. Exit 3 reports either a pending SCM state or `RestartRequired` along
with the original published INF. Any restart remains under operator control.
Use `remove-policy RECEIPT` for the original persistent WFP metadata.

## Driver channel

`device::Device::open` opens the existing exclusive device and attaches an
unnamed auto-reset wake event. During startup, a sharing conflict on the open
can be retried while the original startup deadline remains in force.
`start` validates one through sixteen original
IFS UDP sockets, queries their ALE endpoint identities and submits the exact
native START record. Only successful native acknowledgement constructs
`device::Started`. Keep the actual socket reservations through successful STOP.

Use `event_wait` for the existing native event-wait adapter. Signals coalesce;
one consuming waiter must drain both query and completion queues before
rearming. `read_query` uses caller storage large enough for a whole record.
`write` submits a complete response or token-only discard. Acceptance does not
prove injection completion, receive authorization or application delivery.
`read_completion` returns the original native status and independent receive
gate observation.

`Started::stop` observes one actual STOP attempt and retains its result. Success
acknowledges capture revocation and release of the driver's upstream handle
owners. The same file remains available for outstanding native completions.
Dropping the device closes its file; that is not a native callback-cutoff proof.

## Driver maintenance

Use `device::Maintenance` after the data service has stopped and closed the
packet file. `poll` advances bounded preparation. After
`PreparedForNativeWait`, use `finalize` for the explicit passive native wait.
Continue `finalize` if it reports `Completion`. A `Failed` response carries an
NTSTATUS and keeps the driver's anchor in place. On `NativeRetired`, call
`close` to release the original maintenance handle. The operator command
`stop-driver DIR` pairs a close receipt with the verified SCM service.
`Maintenance::recover_release` can obtain that receipt after native handoff
through a new read-only handle to the original loaded driver. The low-level
`poll-driver` and `finalize-driver` commands perform native rundown for an
independent service controller.

## Upstream identities

`upstream::query` borrows an actual socket and checks its complete Winsock
protocol information, IFS handle support and IPv4/IPv6 UDP type before querying
its nonzero ALE endpoint. Endpoint values and `Started::upstreams` are numeric
observations. They do not replace original socket owners or establish kernel
custody independently of the driver protocol.
