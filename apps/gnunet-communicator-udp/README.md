# UDP communicator PROGRAM

`gnunet-communicator-udp` loads the standard GNUnet configuration and runs the
[native UDP runtime](../../adapters/udp-runtime-std/README.md).

```sh
gnunet-communicator-udp -c /path/to/gnunet.conf
```

On Unix, configured numeric sockets bind before `USERNAME` is applied. Windows
checks the configured account against the current process token. The PROGRAM
owns native signals, inherited client control and the selected logger. It
rejects inherited listener activation.

The communicator reads the existing `[peer] PRIVATE_KEY` only after verifying
the PILS announcement. It reports address changes to TRANSPORT, which publishes
the combined address set through PILS. UDP socket options, replay state, and the application
entry are documented by the [runtime adapter](../../adapters/udp-runtime-std/README.md).
