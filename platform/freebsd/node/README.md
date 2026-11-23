# GNUnet node with FreeBSD rc.d

The staged `gnunet_node` rc.d script uses the base system's `daemon(8)`
supervisor to run the peer as the dedicated local
user `gnunet` with primary group `gnunet`. Install the files at the path selected
by `stage-node --install-prefix` (default `/usr/local`) and keep the executables
and bootstrap data under administrator control. Create the non-login service
account and group before enabling the service.

## Install and run

As root, from the directory containing the staged rc.d script:

```sh
install -d -o root -g wheel -m 0755 /usr/local/etc/rc.d /var/db/gnunet-node
install -d -o gnunet -g gnunet -m 0700 \
  /var/db/gnunet-node/state /var/db/gnunet-node/ipc
install -o root -g wheel -m 0555 gnunet_node /usr/local/etc/rc.d/
sysrc gnunet_node_enable=YES
service gnunet_node start
```

The packaged profile dials outbound TCP and loads any trusted HELLOs from the
staged bootstrap directory. Set `gnunet_node_args` in root-controlled
`rc.conf(5)` to customize arguments. Include the chosen peer mode in the
replacement along with any explicit configuration or DNS settings. For example:

```sh
gnunet_node_args="--tcp-dual-stack 2086 --udp4-bind 0.0.0.0:2086 --udp6-bind '[::]:2086'"
```

`gnunet-node --help` lists the available options. Preserve the state directory
across upgrades. Local IPC is private to the service account.

## Lifecycle

`service gnunet_node status` checks the supervisor using its locked,
root-owned PID file. `service gnunet_node stop` sends SIGTERM to that
supervisor, which forwards it to its child and exits after the child. The
node's `READY` and `STOPPED` messages and diagnostics go to syslog with the tag
`gnunet-node`. The service manager reports supervisor state.
[FreeBSD daemon](https://man.freebsd.org/cgi/man.cgi?query=daemon&sektion=8) ·
[FreeBSD rc.d lifecycle](https://docs.freebsd.org/en/articles/rc-scripting/)
