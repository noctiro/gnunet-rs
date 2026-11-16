use super::*;
use std::{
    future::poll_fn,
    io::{Read, Write},
};
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn read_file(pipe: &io::PipeReader) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(pipe.as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(File::from(pipe.as_handle().try_clone_to_owned()?))
    }
}
fn write_file(pipe: &io::PipeWriter) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(pipe.as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(File::from(pipe.as_handle().try_clone_to_owned()?))
    }
}
#[test]
fn canceled_read_wait_retains_one_original_request_and_real_eof()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (reader, mut writer) = io::pipe()?;
        let mut input = Input::new(read_file(&reader)?, 16)?;
        drop(reader);
        input.begin(1)?;
        check(
            tokio::time::timeout(std::time::Duration::from_millis(10), input.complete())
                .await
                .is_err(),
            "empty native pipe fabricated input",
        )?;
        check(
            input
                .begin(1)
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
            "cancellation admitted a second read",
        )?;
        writer.write_all(&[0xff])?;
        check(
            input.complete().await? == [0xff],
            "original read bytes changed",
        )?;
        drop(writer);
        input.begin(1)?;
        check(
            input.complete().await?.is_empty(),
            "original byte was replayed at EOF",
        )?;
        let mut retirement = input.retire();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            poll_fn(|cx| retirement.poll_closed(cx)),
        )
        .await??;
        check(closed.successful(), "original input close failed")?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn retiring_pending_read_preserves_its_original_data_and_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (reader, mut writer) = io::pipe()?;
        let mut input = Input::new(read_file(&reader)?, 16)?;
        drop(reader);
        input.begin(1)?;
        let mut retirement = input.retire();
        check(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                poll_fn(|cx| retirement.poll_closed(cx)),
            )
            .await
            .is_err(),
            "pending read was reported closed",
        )?;
        writer.write_all(&[0x1a])?;
        drop(writer);
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            poll_fn(|cx| retirement.poll_closed(cx)),
        )
        .await??;
        check(closed.successful(), "retired input close failed")?;
        let transfer = retirement
            .take_transfer()
            .ok_or_else(|| io::Error::other("original transfer lost"))?;
        check(
            transfer.requested() == 1 && transfer.read_bytes() == Some(&[0x1a][..]),
            "pending input observation was discarded",
        )?;
        check(
            retirement.take_transfer().is_none(),
            "original transfer was consumed twice",
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn binary_write_preserves_nul_newlines_and_non_utf8_without_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (mut reader, writer) = io::pipe()?;
        let mut output = Output::new(write_file(&writer)?, 16)?;
        drop(writer);
        let bytes = [0, 0xff, 10, 13, 0x1a];
        output.begin(&bytes)?;
        check(
            output
                .begin(&bytes)
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
            "pending output was admitted again",
        )?;
        check(
            output.complete().await? == bytes.len(),
            "native byte write count changed",
        )?;
        let retired = settle(
            [None, Some(output.retire())],
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await;
        check(retired.get(0).is_none(), "unused port gained a receipt")?;
        check(retired.successful(), "original output flush/close failed")?;
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual)?;
        check(actual == bytes, "binary data was converted or replayed")?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[cfg(windows)]
#[test]
fn original_blocked_read_cancels_on_its_own_thread_and_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (reader, writer) = io::pipe()?;
        let mut input = Input::new(read_file(&reader)?, 16)?;
        drop(reader);
        input.begin(1)?;
        let mut original = input.retire();
        let hard = Instant::now() + std::time::Duration::from_secs(5);
        let alarm = tokio::time::sleep_until(hard.into());
        let mut alarm = std::pin::pin!(alarm);
        let retry = tokio::time::sleep(std::time::Duration::ZERO);
        let mut retry = std::pin::pin!(retry);
        let mut requested = false;
        let closed = poll_fn(|cx| {
            if let Poll::Ready(closed) = original.poll_closed(cx) {
                return Poll::Ready(closed);
            }
            if alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original read did not cancel and close",
                )));
            }
            if !requested && retry.as_mut().poll(cx).is_ready() {
                requested = original.request_read_cancel()?;
                retry
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(10));
                let _registered = retry.as_mut().poll(cx);
            }
            Poll::Pending
        })
        .await?;
        check(
            requested && closed.successful() && closed.observed_at <= hard,
            "a request alone cannot prove original read cancellation or close",
        )?;
        let transfer = original
            .take_transfer()
            .ok_or("missing original canceled read receipt")?;
        check(
            transfer.read_cancelled(),
            "original native read did not report cancellation",
        )?;
        drop(writer);
        Ok(())
    })
}
