//! Original child with inherited parent-control stdin and bounded exit observation.
use super::{Directory, Failure, check};
use std::{
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
pub struct Service(Option<Child>);
impl Service {
    pub fn new() -> Result<Self, Failure> {
        Ok(Self(None))
    }
    pub async fn start(&mut self, directory: &Directory, config: &Path) -> Result<(), Failure> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-service-namecache"));
        command
            .env_clear()
            .envs(directory.environment())
            .env("GNUNET_OS_CONTROL_PIPE", "0")
            .arg("-c")
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.0 = Some(command.spawn()?);
        Ok(())
    }
    async fn wait(&mut self) -> Result<(), Failure> {
        loop {
            let child = self.0.as_mut().ok_or("missing original service child")?;
            if child.try_wait()?.is_some() {
                let output = self
                    .0
                    .take()
                    .ok_or("original child lost")?
                    .wait_with_output()?;
                if !output.status.success() {
                    return Err(format!(
                        "service failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                    .into());
                }
                check(
                    output.stdout.starts_with(b"READY namecache "),
                    "service did not reach real readiness",
                )?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub async fn stop(&mut self) -> Result<(), Failure> {
        let child = self.0.as_mut().ok_or("missing original service child")?;
        let mut control = child
            .stdin
            .take()
            .ok_or("missing original parent control")?;
        control.write_all(&[15])?;
        drop(control);
        self.wait().await
    }
    pub async fn retire(&mut self) -> Result<(), Failure> {
        if let Some(child) = &mut self.0 {
            child.kill()?;
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if child.try_wait()?.is_some() {
                        return Ok::<(), Failure>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await??;
            self.0 = None;
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _stop = child.kill();
            let _reap = child.try_wait();
        }
    }
}
