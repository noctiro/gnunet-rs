# HiSpark Taurus Linux node image

The `openharmony-small-linux` image profile stages the foreground GNUnet peer
for the OpenHarmony `ipcamera_hispark_taurus_linux` product. The board uses
Linux 5.10, ARM Cortex-A7 and the base ARM floating-point calling convention.
The profile links musl statically and verifies the staged executable's ARM
EABI5, byte order and that execution requires no ELF interpreter or shared
libraries. [Product configuration](https://github.com/openharmony/vendor_hisilicon/blob/master/hispark_taurus_linux/config.json) ·
[Board toolchain](https://github.com/openharmony/device_board_hisilicon/blob/master/hispark_taurus/linux/config.gni) ·
[Rust ARMv7 Linux target](https://doc.rust-lang.org/rustc/platform-support.html)

## Stage the image input

Install the `armv7-unknown-linux-musleabi` Rust target and configure Cargo's
matching soft-float Linux musl cross linker. Run this command from the
repository root.

```sh
cargo xtask stage-node-image \
  --profile openharmony-small-linux --target armv7-unknown-linux-musleabi \
  --policy /path/to/taurus-node.json --output target/gnunet-node-taurus
```

Set the user and group to dedicated, non-root IDs allocated by the product.
Both directories must be distinct, private paths under `/storage/data/`.
Create any intermediate directories with trusted ownership before startup.

```json
{
  "uid": 3401,
  "gid": 3401,
  "state_directory": "/storage/data/gnunet-state",
  "ipc_directory": "/storage/data/gnunet-ipc",
  "peer_mode": "outbound-tcp"
}
```

Select `peer_mode: "listening"` to enable listeners. Set either a numeric
`tcp_bind` or a nonzero `tcp_dual_stack` port and set a numeric `udp4_bind`
address. You can also set `udp6_bind`, explicit `dns_servers` endpoints and
immutable `config_file` and `bootstrap_data_directory` paths below `/etc/`.
Install configuration and trusted bootstrap assets in the product image.

## Integrate with the product

Put the staged directory under `vendor/hisilicon/hispark_taurus_linux` and add
its `:gnunet_node_image` target to the vendor product group's `deps`.
The GN targets copy `gnunet-node` to `/bin/gnunet-node` and the configuration
fragment to `/system/etc/init/gnunet-node.cfg`. Keep the product's `/etc/init.cfg`
and existing volume setup. [Vendor product group](https://github.com/openharmony/vendor_hisilicon/blob/master/hispark_taurus_linux/BUILD.gn) ·
[Root filesystem layout](https://github.com/openharmony/vendor_hisilicon/blob/master/hispark_taurus_linux/fs.yml)

The product mounts `/storage` as ext4 and prepares `/storage/data` in `pre-init`.
OpenHarmony Lite init loads the fragment before boot jobs start. Its
`post-init` job creates the two directories with the selected identity and
mode `0700`, then starts the node with `--require-storage-mount /storage`.
Startup requires both directories to belong to the actual `/storage` mount
before opening the peer identity or journals. The stock board configuration
supplies TCP, UDP and Unix sockets. The staged service requests no capabilities.
[Taurus fstab](https://github.com/openharmony/vendor_hisilicon/blob/master/hispark_taurus_linux/init_configs/etc/fstab) ·
[Lite init and boot phases](https://github.com/openharmony/startup_init/blob/master/services/init/lite/init.c) ·
[Taurus kernel profile](https://github.com/openharmony/kernel_linux_config/blob/master/linux-5.10/arch/arm/configs/hispark_taurus_small_defconfig)

## Readiness and shutdown

Observe the process's `READY` receipt after the selected services start.
The product controller retains the original process when requesting
`SIGTERM` and observes both the bounded `STOPPED` result and process exit
before restarting or reclaiming IPC resources. Lite init releases its boot
jobs and this service uses `once: 1`. The product controls any subsequent
start. Confirm the rootfs contents, identity continuity after reboot, and
process retirement on the selected image. [Init service management](https://github.com/openharmony/startup_init/blob/master/services/init/init_common_service.c)
