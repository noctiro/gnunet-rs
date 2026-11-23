# GNS proxy CA preparation

`gnunet-gns-proxy-setup-ca` creates credentials for the GNS proxy and can import
the public CA into existing NSS databases. Shared PROGRAM preparation supplies
configuration, logging and filename expansion on Linux, macOS, FreeBSD and
Windows. `-v` prints the version; `-V` enables verbose preparation; `-t` probes
the provider and optional NSS helper; `-o` repeats a bounded status summary.

## Credential publication

A normal invocation uses OS entropy and RustCrypto P-256 to create a self-signed
P-256/SHA-256 CA. The certificate has the GNS Proxy CA subject, critical CA
constraints, certificate-signing usage and 3650-day validity.
Expanded `[gns-proxy] PROXY_CACERT` receives the certificate and unencrypted
PKCS#8 key in one PEM file. The serialized private key is erased before launching
an NSS helper. Existing destinations, including symlinks, are refused.

Original native directory and file owners protect staging, no-clobber hard-link
publication and cleanup. New parent directories are private; existing permissions
are checked rather than changed. Unix staging uses 0600; Windows uses a private
process-user DACL. Complete writes and file synchronization precede publication.
Attempted publication, confirmed publication, original staging removal, writer
close and directory synchronization have independent results. An error can leave
a published credential; it never triggers replacement or rollback by pathname.
Windows directory synchronization may be unavailable and does not imply durable
name publication. Filesystems without hard links return an error.

## NSS configuration

`[gns-proxy-rust] NSS_CERTUTIL` selects an absolute path to trusted Mozilla NSS
`certutil`. Windows requires this selection for optional imports because the
system program with the same name implements a different interface. Unix can
use NSS `certutil` from PATH. No implicit command shell is used on Windows.
`NSS_DATABASE` optionally selects one existing custom database, including a
profile outside the default browser locations.

Default discovery covers Windows `%APPDATA%/Mozilla/Firefox/Profiles`, macOS
`~/Library/Application Support/Firefox/Profiles`, Unix `~/.mozilla/firefox` and
`~/.mozilla/icecat`, and Unix `~/.pki/nssdb`. Only directories containing an
ordinary `cert9.db` or `cert8.db` are admitted. SQL databases use the `sql:`
prefix. Discovery is limited to 4096 entries and 128 profiles; the original
profile directory remains held and is checked around helper calls. The default
Firefox locations follow the [Mozilla profile service](https://firefox-source-docs.mozilla.org/toolkit/profile/index.html).

Imports pass only a private staging file containing the public certificate, with
the `GNS Proxy CA` nickname and `CT,,` trust flags. Existing nicknames are
preserved. Missing optional helpers/profiles are reported as skips; nonzero
import statuses and changed profile observations are errors. A successful helper
exit does not prove that a running browser has reloaded trust. The command does
not modify operating-system trust stores. See the [NSS tool reference](https://nss-crypto.org/reference/security/nss/legacy/tools/certutil/index.html).

## Cancellation and errors

Native startup captures parent control first. One 120-second native/canonical
window covers preparation, with stop signals, parent control and logger errors
checked between bounded work units. Synchronous filesystem/crypto calls cannot
be forcibly interrupted. A failed or cancelled NSS operation retains the original
child, requests native termination and observes exit for at most five seconds.
Timeout reports an unobserved exit rather than claiming successful retirement.
The full Windows exit word is retained. Public-file removal, writer close,
publication, helper exit and selected diagnostic errors remain independent.

`-t` creates no credential and imports no trust. Actual browser trust and
cross-platform runtime qualification follow the central
[implementation status](../../IMPLEMENTATION_STATUS.md).
