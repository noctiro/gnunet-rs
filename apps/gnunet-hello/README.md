# gnunet-hello

Export, re-sign, import and enumerate public GNUnet HELLO announcements through
PILS and PEERSTORE. Linux, macOS, FreeBSD and Windows share the same command.

## Configuration and examples

Configure the `[pils]` and `[peerstore]` service endpoints in the selected file.
Choose exactly one of `--export-hello`, `--import-hello` or `--dump-hellos`.

```sh
gnunet-hello -c gnunet.conf --export-hello
gnunet-hello -c gnunet.conf --export-hello --binary > hello.bin
gnunet-hello -c gnunet.conf --import-hello < hello.bin
```

`--expiration TIME` requests PILS re-signing during export. Standard PROGRAM
options select logging, configuration, help and version. Neither command action
requires a private-key filename. See the [shared command reference](../../adapters/peer-tools-std/README.md)
for profiles, endpoint overrides and limits.

## Results and cancellation

Export requires the observed announcement or matching signature completion.
Import reports an actual STORE_RESULT or a verified existing newer record.
Enumeration completes at ITERATE_END. Cancellation retires original owners and
retains partial-output and cleanup failures. Public address assertions retain
the signature coverage reported by the codec.
