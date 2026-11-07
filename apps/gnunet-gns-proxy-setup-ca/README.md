# GNS proxy CA preparation

`gnunet-gns-proxy-setup-ca` implements the preparation command described by the
pinned official `src/cli/gns/gnunet-gns-proxy-setup-ca.in` and its man page. Shared PROGRAM preparation supplies configuration, help/version, logging and
filename expansion. Official `-v` prints the version; `-V` selects verbose
preparation. `-c FILE`, `-h`, `-t`, and `-o` retain their respective purposes.

A normal invocation generates a self-signed P-256/SHA-256 CA with the official
GNS Proxy CA subject and 3650-day validity. It includes explicit critical CA
constraints and certificate-signing key usage, and emits one certificate plus
one unencrypted PKCS#8 key (standard 64-column PEM encoded by the existing
Base64 dependency) into expanded `[gns-proxy] PROXY_CACERT`. This ordinary
X.509 profile is consumable by the Rust proxy authority loader and compatible
TLS consumers.

The combined credential is staged with create-new 0600 permissions in the same
directory and published using a no-clobber hard link after complete writes and
file synchronization. New parent directories use 0700; existing directories are
not chmodded. An existing destination, including any symlink, is preserved and
reported as a refusal. There is no automatic CA rotation or existing-private-key
read. Publication/cleanup/durability failures retain whether the new destination
was actually published. Filesystems without same-directory hard links return a
error rather than silently using an overwrite-prone fallback.

For Firefox/Icecat `~/.mozilla/*/*.*` profile directories and `~/.pki/nssdb`, the
optional NSS `certutil` adapter imports only the public certificate with the
standard GNS Proxy CA nickname and CT,, trust flags. SQL databases use the sql:
prefix. An existing nickname is preserved and returned as an explicit import refusal,
rather than deleted or treated as proof that this new CA is already trusted. Missing helpers/profiles are explicit skips. Actual nonzero import statuses are
errors; a successfully created CA remains available after browser import failure. The helper does not change a system-wide trust store. Browser software must
actually use the discovered NSS database; successful certutil status is not a
claim that every browser or running profile has reloaded trust.

`-t` reports the compiled rcgen/AWS-LC provider and runs the optional certutil
help probe. It creates no CA, imports no trust and requires no OpenSSL/GnuTLS
binary. `-o` retains a bounded in-memory status summary, with no temporary summary
file. Profiles, scanned directory entries, paths and generated PEM sizes are
bounded. One original 120-second native/canonical window covers preparation and
subprocess polling without phase renewal. Synchronous filesystem/cryptographic
calls are guarded before/after but cannot be forcibly preempted; an NSS child is
killed and reaped on guard failure before its error is returned.

C/Rust/browser acceptance remains open.
