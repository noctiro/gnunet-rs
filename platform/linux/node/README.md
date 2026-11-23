# GNUnet node with systemd

The staged `gnunet-node.service` runs the peer as the dedicated system user
and group `gnunet`. Install the files at the path selected by
`stage-node --install-prefix` (default `/usr/local`) and keep the executables
and bootstrap data under administrator control. Create the service account and
group before loading the unit. Systemd owns the creation and modes
of `/var/lib/gnunet-node` and `/run/gnunet-node`. Preserve the state directory
across upgrades. Local IPC is private to the service account.

## Install and run

From the directory containing the staged service file:

```sh
sudo install -o root -g root -m 0644 gnunet-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gnunet-node.service
journalctl -u gnunet-node.service
```

The packaged profile dials outbound TCP and loads any trusted HELLOs from the
staged bootstrap directory. To change it, use an administrator-owned systemd
drop-in with an empty `ExecStart=` followed by the complete replacement
`ExecStart=`. Preserve the leading `--systemd` and both private directory
options. `gnunet-node --help` lists listening, explicit configuration and
numeric DNS upstream options.

## Lifecycle

`systemctl start` waits for the node's readiness barrier. For shutdown use
`sudo systemctl stop gnunet-node.service`. The manager sends SIGTERM and allows
the node up to 30 seconds to retire. Use the journal for service transitions
and process diagnostics. Increase the corresponding unit timeout if you
increase the node's startup or drain budget.
[systemd service lifecycle](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) ·
[systemd directory ownership](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
