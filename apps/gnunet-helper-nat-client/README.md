# gnunet-helper-nat-client

Send the two official GNUnet reversal variants using the shared
[native helper implementation](../../adapters/nat-helper-std/).

## Arguments and result

```text
gnunet-helper-nat-client LOCAL_IP REMOTE_IP PORT
```

Addresses are numeric IPv4 and the port is decimal `1..65535`. There is no stdin
or stdout protocol. Both packets share one fixed five-second send budget. Exit
zero proves both whole local writes; errors, short writes and cancellation
remain failures and establish no remote receipt or connectivity.

## Platforms and privileges

Linux, macOS, FreeBSD 12+ and Windows select native backends using the same
packet algorithms. Unix opens raw resources before permanently dropping to the
invoking IDs and applicable Linux capability policy. Windows uses the invoking
token's existing raw-socket permission and performs no elevation. See the host
for exact credential, lifetime and cleanup contracts.
