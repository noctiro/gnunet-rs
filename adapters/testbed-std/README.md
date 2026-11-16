# TESTBED configuration and port planning

This adapter generates ordinary GNUnet configurations for isolated peers. The
caller owns one `System`, its fixed logical `PortSlot` pool and the generated
configurations. Peer startup and shutdown use the service runtime and ARM.

## Root ownership and restart

`System::create` selects a new, empty or exactly marked private directory. An
explicit `Options.prefix` takes precedence over a fresh child of
`Options.temporary_parent`. Defaults use a short Unix `/tmp` parent or the native
Windows temporary directory. `Options::from_environment` selects the official
`GNUNET_TESTBED_PREFIX` override.

The owner holds the original parent/root directories, marker file and exclusively
locked file. Marker contents, native identity and private Unix permissions or
Windows DACLs are checked. Root or marker/lock replacement refuses new effects.
The checked counter is synchronized and atomically published before each numbered
home is created. Missing or corrupt counters in an existing marked root are
errors. Existing numbered homes are never overwritten.

## Configuration generation

`configuration_create` duplicates the loaded CONFIG, creates a private home and
sets `PATHS.DEFAULTCONFIG`, `ARM.CONFIG`, `PATHS.GNUNET_HOME`, selected `PORT`,
`UNIXPATH`, `HOSTNAME`, service ACLs and `NAT.USE_LOCALADDR`. Native paths use the
shared lossless byte encoding. Generated socket paths must fit the actual native
address representation. The canonical home remains held through publication;
a replacement at the same path cannot receive its configuration bytes. Official CONFIG
serialization omits loader-derived `PATHS.DEFAULTCONFIG`; reloading initializes
it from the selected filename. Serialized `ARM.CONFIG` retains the canonical
path.

`single_<service>_per_host` retains the configured port/socket. The selected
reference has no implemented `num_<service>_per_host` sharding semantics, so
nonzero sharding requests return `SharedServiceSharding`. Unshared nonzero port
fields each receive an exact logical reservation. A refused generation releases
its reservations and attempts removal of its original empty home; the path number
remains consumed.

## Port reservations

`reserve_port` simultaneously probes TCP and UDP wildcard binds for the enabled
supported IPv4/IPv6 families. IPv6 probes use v6-only sockets; Windows probes use
exclusive address binding. Unsupported native family/option errors remain
distinct from other failures. Probe sockets close before return.

A `Reservation` records a past bind observation and logical exclusion within one
system. It does not reserve the kernel port for a future service. The caller
coordinates its peers and handles later bind failures.

## Publication and cleanup

`write_configuration` serializes CONFIG into zeroizing storage and uses the
shared native publication owner for private staging, complete writes, file
synchronization, consuming writer close and atomic replacement/no-clobber linking.
`Published` contains the selected path, byte count and separate `directory_sync`
observation. Windows can report directory synchronization as unavailable; a
successful file sync alone is not a durable-name receipt.

Failures retain unchanged, staged, uncertain or installed exposure and the native
publication error, including independent writer-close/staging-cleanup results.
Uncertain or failed installed effects fence subsequent admission on that system.
Canonical and exported configurations are separate publications.

`release_configuration` releases logical port reservations. `destroy(false)`
keeps paths; `destroy(true)` removes the original marked tree after the caller
has stopped its external users and excluded namespace administration. Removal
walks held native directories, checks original child identity and never traverses
symlink targets. Marker/lock/counter metadata remain until ordinary contents are
removed. Cleanup errors preserve the first cause and independent failure count.
Standard owner Drop releases remaining handles without claiming a close-errno or
successful tree-removal receipt.

## Resource limits

`Limits` bounds configuration attempts, ports per configuration, serialized and
native path bytes, directory-name attempts, cleanup entries and cleanup depth.
Defaults allow 4096 configurations, 256 ports each, 4 MiB serialized configs,
4096 native path bytes, 4096 directory-name attempts, 131072 cleanup entries and
64 directory levels. Limit exhaustion is an error and can leave owned paths for
explicit recovery. Filesystem operations are synchronous and may block in the OS.
