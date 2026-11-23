# GNUnet node in an Android system image

This vendor-image package runs the [foreground GNUnet node](../../../apps/gnunet-node/README.md)
under Android init. The board owns the system image, service identity and
enforcing SELinux policy. For a regular Android application, use the
[Android SDK](../README.md).

## Include in the vendor image

Stage the [Android image input](../../../tools/xtask/node/README.md#stage-a-system-image-input)
for the board's primary Android ABI and minimum API level. Keep the generated
`Android.bp`, `gnunet-node.rc`, `LICENSE` and `gnunet-node` ELF together in
the board's Soong source tree. The Soong module checks the
prebuilt against the image's native libraries. Add it to the board product
makefile. Export the containing namespace with `PRODUCT_SOONG_NAMESPACES`
if the board uses an explicit Soong namespace.

```make
PRODUCT_PACKAGES += gnunet-node
```

The module installs `/vendor/bin/gnunet-node` and
`/vendor/etc/init/gnunet-node.rc`. The shipped profile dials outbound TCP.
It requests no ambient capabilities. The board can supply explicit
configuration, numeric DNS upstreams or a data directory of trusted bootstrap
HELLOs using the foreground node's documented options.
[Soong prebuilt binaries](https://android.googlesource.com/platform/build/soong/%2B/master/cc/prebuilt.go)

## Service identity and policy

Reserve an unused vendor Android ID and expose it as `vendor_gnunet`.
Add the board's AID file to `TARGET_FS_CONFIG_GEN`. The service uses that
identity for its user and primary group, with `inet` as a secondary group.
For example, use this board AID entry if 2901 is available.

```ini
[AID_VENDOR_GNUNET]
value: 2901
```

Init creates owner-only state and IPC directories beneath the root-owned
`/data/vendor/gnunet` during `post-fs-data`. Preserve the persistent state
directory across upgrades to retain the peer identity. Keep Unix socket
clients within the service's owner-only IPC policy.
[AOSP filesystem identities](https://source.android.com/docs/core/permissions/filesystem#configure-aids)

Include the board's vendor policy directory in `BOARD_VENDOR_SEPOLICY_DIRS`.
Give the executable a dedicated entrypoint type and init domain transition.
Label the state and IPC subtree with a dedicated data type.

```selinux
type vendor_gnunet, domain;
type vendor_gnunet_exec, exec_type, vendor_file_type, file_type;
type vendor_gnunet_data_file, file_type, data_file_type;
init_daemon_domain(vendor_gnunet)
net_domain(vendor_gnunet)
```

Add matching board `file_contexts` entries.

```text
/vendor/bin/gnunet-node      u:object_r:vendor_gnunet_exec:s0
/data/vendor/gnunet(/.*)?   u:object_r:vendor_gnunet_data_file:s0
```

The board policy grants its vendor init context the required directory creation
and ownership operations on this subtree. Give the service only the private
file, directory and self-IPC access the node requires and read access to any
board-supplied configuration or bootstrap files. Qualify these rules with
SELinux enforcing on the selected Android branch.
[AOSP service labeling](https://source.android.com/docs/security/features/selinux/device-policy#label_new_services_and_address_denials)

Allow a read-only route netlink subscription in this service domain if the
board uses native address change notifications. The node continues its timed
interface scans when the system refuses the subscription.

## Optional ICMP traversal

Stage with `--include-nat-helpers` and keep both helper ELFs beside the node
ELF. Soong includes the client and observer as required vendor modules. Init
passes `--nat-helpers-directory /vendor/bin` to the node.

Assign `CAP_NET_RAW` to the two immutable helper executables through the
board's filesystem policy. Verify that the filesystem and execution policy
honor those capabilities and that the capability bounding set retains
`CAP_NET_RAW` for the helper launches. Define helper executable labels and an
enforcing SELinux domain with access to the original raw sockets, UDP probes,
and supervision pipes and process operations. The helpers drop their capability
sets after opening their original raw sockets.
[AOSP filesystem capabilities](https://source.android.com/docs/core/permissions/filesystem) ·
[AOSP service labeling](https://source.android.com/docs/security/features/selinux/device-policy#label_new_services_and_address_denials)

For inbound reversal, select listening endpoints and verify the corresponding
NAT registration. On the target image, check helper launch under the service
identity, traversal with an official peer, and helper retirement when the
interface disappears or the node stops.

## Lifecycle

Init starts the service in `late_start` after its private directories have been
created. The service has a 30-second restart period. Init reports process
state through `init.svc.vendor.gnunet-node`. Foreground output is available
when the board has configured a receiver for the node's output.

The init service uses `gentle_kill`. AOSP init normally sends SIGTERM and
escalates to SIGKILL after 200 ms. That bound can expire during the node's
foreground drain. A board deployment requiring orderly retirement must allow
the foreground process to run through its `STOPPED` result before forcing
termination.
[Android init service options](https://android.googlesource.com/platform/system/core/%2B/master/init/README.md)
