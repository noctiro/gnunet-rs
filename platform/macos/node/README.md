# GNUnet node with launchd

The staged `org.gnunet.node.plist` LaunchDaemon runs the peer at boot as the
dedicated local user and group `gnunet`.
Install the files at the path selected by `stage-node --install-prefix`
(default `/usr/local`) and keep the executables and bootstrap data under
administrator control.
Create the non-login service account and group before loading the job.

## Install and run

From the directory containing the staged property list:

```sh
sudo install -d -o root -g wheel -m 0755 /var/db/gnunet-node /var/log/gnunet-node
sudo install -d -o gnunet -g gnunet -m 0700 \
  /var/db/gnunet-node/state /var/db/gnunet-node/ipc
plutil -lint org.gnunet.node.plist
sudo install -o root -g wheel -m 0644 org.gnunet.node.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/org.gnunet.node.plist
sudo launchctl print system/org.gnunet.node
```

The packaged profile dials outbound TCP and loads any trusted HELLOs from the
staged bootstrap directory. Edit `ProgramArguments` before loading the job to
select a different peer mode, explicit configuration file or numeric DNS
upstreams. Use one array entry per argument as shown in the plist.
`gnunet-node --help` lists the available options. Preserve the state directory
across upgrades. Local IPC is private to the service account.

## Lifecycle

Use `sudo launchctl bootout system/org.gnunet.node` to unload the job and stop
its process. Launchd gives the node up to 30 seconds after SIGTERM to retire.
The job's launchd state describes the process. Use
`/var/log/gnunet-node/stdout.log` for the node's `READY` and `STOPPED` messages,
and `stderr.log` in the same directory for diagnostics. The node restarts on
failure while the job remains loaded.
[Apple launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
