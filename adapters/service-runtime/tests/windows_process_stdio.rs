//! Original overlapped parent stdin and synchronous child-end qualification.
#[cfg(windows)]
mod windows {
    use gnunet_service_runtime::pipe::InputWriter;
    use std::{
        io::{self, Read},
        time::Duration,
    };
    use tokio::io::AsyncWriteExt;

    #[test]
    fn parent_input_preserves_binary_bytes() -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (parent, mut child) = gnunet_native::pipe::input_pair()?;
                let mut parent = InputWriter::new(parent)?;
                // Below the reserved pipe buffer, so this synchronous fixture read
                // consumes an already-submitted native write without another worker.
                let expected: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
                tokio::time::timeout(Duration::from_secs(2), parent.write_all(&expected)).await??;
                let mut actual = vec![0; expected.len()];
                child.read_exact(&mut actual)?;
                if actual != expected {
                    return Err(io::Error::other("original stdin pipe changed binary bytes").into());
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
}
