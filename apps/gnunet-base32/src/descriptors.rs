//! Platform stdio ownership behind one byte-stream conversion interface.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::Descriptor;
#[cfg(windows)]
mod windows;
use std::fmt;
#[cfg(unix)]
use std::io;
#[cfg(windows)]
pub(super) use windows::Descriptor;

/// Independent original input/output retirement, never a cancellation claim.
#[derive(Debug)]
pub(super) struct Closed {
    #[cfg(unix)]
    input_restore: Option<io::Error>,
    #[cfg(unix)]
    output_restore: Option<io::Error>,
    #[cfg(windows)]
    native: gnunet_program_host::binary_io::RetiredSet<2>,
}
impl Closed {
    pub(super) fn successful(&self) -> bool {
        #[cfg(unix)]
        {
            self.input_restore.is_none() && self.output_restore.is_none()
        }
        #[cfg(windows)]
        {
            self.native.successful()
        }
    }
}
impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original Base32 stdio retirement: {self:?}")
    }
}
impl std::error::Error for Closed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(unix)]
        {
            self.output_restore
                .as_ref()
                .or(self.input_restore.as_ref())
                .map(|error| error as _)
        }
        #[cfg(windows)]
        {
            (!self.native.successful()).then_some(&self.native as _)
        }
    }
}
pub(super) async fn close(mut input: Descriptor, mut output: Descriptor) -> Closed {
    #[cfg(unix)]
    {
        Closed {
            output_restore: output.close(),
            input_restore: input.close(),
        }
    }
    #[cfg(windows)]
    {
        let hard = std::time::Instant::now() + std::time::Duration::from_secs(3);
        Closed {
            native: gnunet_program_host::binary_io::settle([input.retire(), output.retire()], hard)
                .await,
        }
    }
}
