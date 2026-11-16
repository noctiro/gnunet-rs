# DNS2GNS PROGRAM

`gnunet-dns2gns` runs the bounded DNS2GNS UDP gateway on Linux, macOS,
FreeBSD and Windows. The [gateway host](../../adapters/dns2gns-std/README.md)
owns GNS routing, ordinary DNS forwarding and VPN allocation.

## Configuration and invocation

```sh
gnunet-dns2gns -c gateway.conf -d 127.0.0.1
```

`-d/--dns` is the required numeric recursive DNS upstream, using port 53.
The example requires a recursive DNS server on localhost. Standard PROGRAM
options `-c`, `-L`, `-l`, `-h` and `-v` select configuration, diagnostics,
help and version.

```ini
[DNS2GNS]
BIND_TO = 127.0.0.1
BIND_TO6 = ::1
PORT = 15353
```

Both listener addresses are required and numeric. Each family binds independently;
either may run, and each original bind error remains available. Missing `PORT`
falls back to 53; explicit zero requests an ephemeral port. Installed `gns.conf`
selects port 15353 separately. Its launcher `OPTIONS` do not replace the manual
command's required upstream argument. GNS, IDENTITY and VPN IPC endpoints use the
shared GNUnet configuration.

## Native startup and shutdown

The executable captures original process inheritance before other native owners,
refuses inherited service listeners, and uses the shared native termination and
parent-control subscriptions. Windows checks a configured `USERNAME` against the
primary process-token SID before starting the gateway. An already observed stop
prevents listener creation.

Ctrl-C, native termination, parent control, scheduler cancellation and fatal
errors stop the same gateway and Resolver owners. The first close fixes a
five-second native observation bound. Remaining work is reported as unresolved;
that bound does not prove remote DNS completion or revoke an allocated VPN lease.
Selected logging and original signal, gateway, Resolver and cleanup errors remain
independent. Native standard-stream calls retain OS blocking semantics.

## Resource and routing constraints

One SharedClock and Resolver context supply all CLIENT selectors. Defaults retain
64 requests, a fixed 60-second query lifetime and a requested 30-minute VPN lease.
Resolver capacity is 16 request slots and 64 name slots; the process clock permits
4096 subscriptions. Progress does not renew original deadlines. Temporary IDNA
scratch is released before asynchronous waiting.

Only a `NotGns` result permits ordinary DNS forwarding. Per-request errors leave
healthy listeners running. Isolated native UDP errors retain their listener and
bounded diagnostics; Windows disables ICMP-induced connection resets before bind.
Diagnostics contain metadata and causes, without DNS names or packet bodies.
The process retains four additional diagnostic request reports and counts omitted
reports without retaining an unbounded history.

## Source contract

The ordinary command profile follows GNUnet v0.29.1
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/service/gns/gnunet-dns2gns.c`. Protocol qualification follows the shared
[compatibility contract](../../spec/gnunet/compatibility.md).
