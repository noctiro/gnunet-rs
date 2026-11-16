//! Real helper byte-pipe ownership without raw sockets or elevation.
#[cfg(windows)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Native fixtures assert independent byte, capacity and lifetime properties while preserving setup/cleanup errors"
)]
mod windows {
    use gnunet_native::{
        nat_helper::{Output, State},
        pipe::output_pair,
    };
    use gnunet_service_runtime::pipe::OutputReader;
    use std::{
        io,
        time::{Duration, Instant},
    };
    use tokio::io::AsyncReadExt;

    #[test]
    fn original_reader_delivers_bytes_and_closure_fences_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (reader, writer) = output_pair()?;
                let mut reader = OutputReader::new(reader)?;
                let mut output = Output::capture(writer)?;
                let bytes = b"127.0.0.1:4242\n";
                let until = Instant::now() + Duration::from_secs(2);
                let mut written = 0;
                while written < bytes.len() {
                    match output.write(&bytes[written..]) {
                        Ok(count) => written += count,

                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= until {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "original pipe write did not complete",
                                ));
                            }
                            tokio::task::yield_now().await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                let mut received = [0; 15];
                tokio::time::timeout(
                    Duration::from_secs(2),
                    reader.read_exact(&mut received[..bytes.len()]),
                )
                .await??;
                assert_eq!(
                    &received[..bytes.len()],
                    bytes,
                    "same original pipe must carry exact protocol bytes"
                );
                drop(reader);
                let until = Instant::now() + Duration::from_secs(2);
                loop {
                    if output.state()? == State::Closed {
                        break;
                    }
                    if Instant::now() >= until {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original reader closure was not observed",
                        ));
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(
                    output.write(b"stale\n").err().map(|error| error.kind()),
                    Some(io::ErrorKind::BrokenPipe),
                    "closed generation must admit no replacement output"
                );
                output.restore()?;
                Ok::<_, io::Error>(())
            })?;
        Ok(())
    }

    #[test]
    fn full_original_pipe_refuses_more_output_and_restore_fences_admission() -> io::Result<()> {
        let (reader, writer) = output_pair()?;
        let mut output = Output::capture(writer)?;
        let bytes = [b'x'; 512];
        let until = Instant::now() + Duration::from_secs(2);
        let mut written = 0;
        loop {
            match output.write(&bytes) {
                Ok(count) => written += count,

                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if written != 0 {
                        break;
                    }
                    if Instant::now() >= until {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    std::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
            assert!(
                written <= 65536,
                "nonblocking byte pipe must apply its native capacity"
            );
        }
        output.restore()?;
        assert_eq!(
            output.write(b"late").err().map(|error| error.kind()),
            Some(io::ErrorKind::BrokenPipe),
            "restoration closes this output owner's admission"
        );
        drop(reader);
        Ok(())
    }
}
