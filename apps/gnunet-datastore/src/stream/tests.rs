//! Cancellation must leave actual native effects with the outer command owner.
use super::*;
use std::{fs::File, io::Write};

fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

#[test]
fn dropped_stream_and_canceled_settle_retain_original_transfer() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (reader, mut writer) = io::pipe()?;
        #[cfg(unix)]
        let file = {
            use std::os::fd::AsFd;
            File::from(reader.as_fd().try_clone_to_owned()?)
        };
        #[cfg(windows)]
        let file = {
            use std::os::windows::io::AsHandle;
            File::from(reader.as_handle().try_clone_to_owned()?)
        };
        drop(reader);
        let mut input = Input::new(file, CHUNK)?;
        input.begin(1)?;
        let retained = retained();
        let slot = retained.borrow_mut().reserve()?;
        let stream = Stream {
            endpoint: Some((Endpoint::Input(input), Box::new_uninit())),
            retained: retained.clone(),
            slot,
        };
        drop(stream);
        let until = retained
            .borrow()
            .first_error()
            .ok_or("retirement lost on Drop")?
            .until;
        check(
            tokio::time::timeout(Duration::from_millis(10), settle(&retained))
                .await
                .is_err(),
            "pending original read was reported closed",
        )?;
        writer.write_all(&[0xff])?;
        drop(writer);
        tokio::time::timeout(Duration::from_secs(2), settle(&retained)).await?;
        let cleanup = retained.borrow();
        let error = cleanup
            .first_error()
            .ok_or("unclaimed native transfer was discarded")?;
        check(
            cleanup.failed(),
            "unclaimed transfer became command success",
        )?;
        check(
            error.until == until && !error.late,
            "original cleanup deadline changed",
        )?;
        check(
            error.retirement.is_none(),
            "original close was not observed",
        )?;
        check(
            error.report.as_ref().is_some_and(Closed::successful),
            "native close failed",
        )?;
        check(
            error.transfer.as_ref().and_then(NativeTransfer::read_bytes) == Some(&[0xff][..]),
            "original read completion/data was lost",
        )?;
        Ok::<(), Failure>(())
    })
}
