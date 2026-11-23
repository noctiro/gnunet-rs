# OpenHarmony native node image

This recipe installs the foreground Rust `gnunet-node` executable into an
OpenHarmony standard-system image. It uses the same node and GNUnet protocols
as the application SDK. The image integrator selects the identity, peer
transport profile, directories and network policy explicitly.

For the Linux small system on HiSpark Taurus, use the
[small-system image recipe](small-linux/README.md).

## Stage and include the recipe

Use the repository's [native node staging guide](../../../tools/xtask/node/README.md)
and `cargo xtask stage-node-image` with an OpenHarmony target and `--policy`.
The tool produces adjacent `gnunet-node`, `BUILD.gn` and `gnunet-node.cfg`
files. Keep them together under the selected product source directory and add
its `:gnunet_node_image` target to the owning part's `module_list`. Select that
part in the product. The executable is copied to `/system/bin/gnunet-node`;
the configuration goes to `/system/etc/init/gnunet-node.cfg`.
[OpenHarmony part registration](https://github.com/openharmony/build/blob/master/docs/标准系统如何添加一个模块.md)
and [prebuilt templates](https://github.com/openharmony/build/blob/master/templates/cxx/prebuilt.gni)
define these build interfaces.

The templates are inputs to the shared staging command, not directly usable
init files. `BUILD.gn.in` receives the explicit `PART` and `SUBSYSTEM`.
`gnunet-node.cfg.in` receives numeric `UID` and `GID`, `SELINUX_CONTEXT`,
`STATE_DIRECTORY`, `IPC_DIRECTORY` and the complete JSON `ARGUMENTS` array,
including `/system/bin/gnunet-node` as its first element. Init limits that array
to 20 strings of at most 64 UTF-8 bytes each. Unknown policy fields, unsafe
literal paths and conflicting transport options are rejected by the staging
command. [Init service configuration](https://github.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-boot-init-service.md)

## Identity and private storage

Reserve a dedicated UID and GID in the product's account policy. Supply a
matching native SELinux domain, executable file context, data and IPC labels,
and the precise network/filesystem rules the selected profile needs. The
recipe requests `ohos.permission.INTERNET`, normal ability privilege and no
Linux capabilities. It retains the native sandbox. It grants no service-control
permission to the node. Those image rules and account allocations remain
product inputs; substituting a context string does not install SELinux policy.

The state and IPC paths must be distinct private directories below `/data`.
Provision their mounted parent directories first, with trusted ownership and
no symlinks or replacement access by other identities. The custom init job
creates each final directory and sets mode `0700` and the chosen owner. It
does not recursively change ancestors or existing contents. Keep persistent
identity and journals in the state directory across restarts. Optional config
and bootstrap assets must be installed at their selected immutable image paths
and readable by this identity. The image recipe does not fetch assets.

## Optional ICMP traversal

Stage with `--include-nat-helpers` and keep both helper ELFs alongside the
node. The image target installs them under `/system/bin` and init passes
`--nat-helpers-directory /system/bin` to the node.

Use the selected image's filesystem policy to assign `CAP_NET_RAW` to the
two immutable helper executables. Verify that the filesystem and execution
policy honor those capabilities and that the capability bounding set retains
`CAP_NET_RAW` for helper launches. Supply enforcing helper labels and a domain
that permits the required raw sockets, UDP probes, and supervision pipes and
process operations. The helper discards its capabilities after opening the
raw sockets. Qualify the permission and sandbox behavior on the product image.
[OpenHarmony SELinux integration](https://github.com/openharmony/security_selinux_adapter/blob/master/README-en.md) ·
[Init service configuration](https://github.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-boot-init-service.md)

For inbound reversal, choose a listening peer mode and verify the NAT
registration. Check helper launch under the service identity, traversal with
an official peer, and retirement on interface removal and node stop.

## Start and readiness

After mounting and labeling the private data parents, have the product's
selected init job execute `trigger gnunet-node-start`. That custom job prepares
both directories before issuing `start gnunet-node`; do not bypass it on the
first start. There is no implicit boot trigger. `start-mode=condition` and
`once=1` keep startup and restart under the product controller. Custom init
jobs are explicitly triggered; commands from different files sharing a job
name have no general ordering guarantee.
[Init job management](https://github.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-boot-init-jobs.md)

The node stays in the foreground and emits `READY` only after its selected
native services start. Init's process-start status is not this readiness
receipt. The product must arrange stdout/stderr collection and observe the
actual node result; this recipe does not configure a console or invent a
system-ability readiness notification. Choose outbound TCP for a listener-free
peer profile, or the explicit listening endpoints in the image policy. Raw
resolver endpoints are optional explicit inputs, not automatically derived
from a tunnel or encrypted DNS setting.

## Stop, restart and recovery

For orderly shutdown, an authorized product controller can use the platform
innerkit `ServiceControl("gnunet-node", TERM)` on an image whose init supports
that action. This sends `SIGTERM`, which starts the node's bounded drain.
[Service-control implementation](https://github.com/openharmony/startup_init/blob/master/interfaces/innerkits/service_control/service_control.c)

Current standard-system init publishes `SERVICE_STOPPED` immediately after
sending the signal; this is not proof that the original process exited.
Retain actual process-exit tracking before requesting termination, await the
original process, and distinguish a successful node `STOPPED` result from an
error or timeout. Only then start another instance or remove its IPC files.
The template's `once=1` prevents automatic respawn.
[Init termination implementation](https://github.com/openharmony/startup_init/blob/master/services/init/init_common_service.c)

The ordinary init `stop`/`STOP` action selects `SIGKILL` for `gnunet-node` in
the current platform implementation; it supplies no drain receipt. After
`TERM`, init has already discarded its PID, so a later `STOP` cannot be relied
on to kill that original process. A controller that requires a forced deadline
must retain an authorized stable process handle and terminate that exact
process itself. Never treat a forced stop, reboot or init status change as
permission to delete persistent state.
[Init stop signal selection](https://github.com/openharmony/startup_init/blob/master/services/init/init_service_manager.c)

## Image qualification

Build the rendered targets with the selected product's GN toolchain and verify
the installed executable, init file, account allocation, access token, SELinux
labels, sandbox visibility and private-directory ownership on that image.
Exercise actual startup, readiness, termination, bounded forced-stop recovery
and reboot before selecting a boot trigger. Template rendering and JSON
validation do not establish device permission or shutdown behavior.
