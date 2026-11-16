use super::*;
use crate::terminal::Descriptor;
use gnunet_service_runtime::process;
use std::os::fd::AsFd;
pub(super) type Record = Descriptor;
pub(super) type PlaybackPipe = Descriptor;
pub(super) fn stop_child(
    registry: &mut ChildRegistry,
    child: &OriginalChild,
    force: bool,
) -> Result<(), Failure> {
    registry.signal_native(
        child,
        if force {
            nix::libc::SIGKILL
        } else {
            nix::libc::SIGTERM
        },
    )?;
    Ok(())
}
pub(super) fn cancelled(_error: &std::io::Error) -> bool {
    false
}
impl Media {
    pub(super) fn launch(
        &mut self,
        bounds: Bounds,
        c: &gnunet_config::Configuration,
        s: &Settings,
    ) -> Result<(), Failure> {
        let clock = self.clock.clone();
        let (rec_read, rec_write) = process::pipe()?;
        let (play_read, play_write) = process::pipe()?;
        for fd in [&rec_write, &play_read] {
            use nix::fcntl::{FcntlArg, OFlag, fcntl};
            let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
            fcntl(fd, FcntlArg::F_SETFL(flags & !OFlag::O_NONBLOCK))?;
        }
        self.record = Some(Descriptor::pipe(rec_read)?);
        self.playback = Some(Descriptor::pipe(play_write)?);
        let spawn = |path: &std::path::Path,
                     mapping: process::DescriptorMap<'_>,
                     registry: &mut ChildRegistry|
         -> Result<OriginalChild, Failure> {
            let filename = path.as_os_str().to_os_string();
            let command = process::NativeCommand {
                filename: filename.clone(),
                argv: vec![filename],
                environment: process::EnvironmentSnapshot::system()?,
                environment_changes: Vec::new(),
                cwd: None,
                stdio: 4,
                stdio_snapshot: None,
                listeners: Vec::new(),
                mappings: vec![mapping],
            };
            // Same original call budget after synchronous environment /
            // descriptor preparation, including before the second child.
            bounds.check(clock.as_ref())?;
            match process::spawn(
                c,
                &s.launcher,
                command,
                process::ProcessLimits {
                    launch: process::LaunchLimits {
                        max_children: 2,
                        max_arguments: 8,
                        max_command_bytes: 16384,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                registry,
            )? {
                process::SpawnResult::Admitted(child) => Ok(child.child),
                process::SpawnResult::Refused { error: Some(e) } => Err(e.into()),
                process::SpawnResult::Refused { error: None } => {
                    Err("media executable/native admission was refused without a child".into())
                }
            }
        };
        let child = spawn(
            &s.record,
            process::DescriptorMap {
                source: rec_write.as_fd(),
                target: 1,
            },
            &mut self.registry,
        )?;
        self.report
            .as_mut()
            .ok_or("media report missing after actual admission")?
            .record_child = Some(child);
        let child = spawn(
            &s.playback,
            process::DescriptorMap {
                source: play_read.as_fd(),
                target: 0,
            },
            &mut self.registry,
        )?;
        self.report
            .as_mut()
            .ok_or("media report missing after actual admission")?
            .playback_child = Some(child);
        Ok(())
    }
}
