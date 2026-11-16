//! Original nonblocking byte-pipe output and physical reader lifetime.
use std::{
    fs::File,
    io::{self, Write},
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle},
};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FILE_PIPE_CLOSING_STATE, FILE_PIPE_CONNECTED_STATE, FILE_PIPE_DISCONNECTED_STATE,
        FILE_PIPE_LOCAL_INFORMATION, FilePipeLocalInformation, NtQueryInformationFile,
    },
    Win32::{
        Foundation::RtlNtStatusToDosError,
        Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType},
        System::{
            IO::IO_STATUS_BLOCK,
            Pipes::{
                GetNamedPipeHandleStateW, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
                SetNamedPipeHandleState,
            },
        },
    },
};
/// Physical state of the same original byte-pipe reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// The original reader endpoint remains connected.
    Connected,
    /// The original reader endpoint has physically closed.
    Closed,
}
enum Mode {
    Nonblocking(u32),
    Restored,
    Closed,
}
/// Exclusive protocol output from a qualified local byte pipe. The writer
/// requires read-attribute rights, as supplied by [`crate::pipe::output_pair`].
/// Reader closure fences this generation; a live endpoint's mode is restored.
pub struct Output {
    file: File,
    mode: Mode,
}
impl Output {
    /// Capture stdout once, excluding other writers and route mutation while live.
    pub fn stdout() -> io::Result<Self> {
        Self::capture(File::from(io::stdout().as_handle().try_clone_to_owned()?))
    }
    /// Adopt a qualified original writer without a thread or replacement pipe.
    #[expect(
        unsafe_code,
        reason = "Native pipe queries/options borrow the owned handle and initialized scalar storage"
    )]
    pub fn capture(file: File) -> io::Result<Self> {
        // SAFETY: original owned file remains live throughout the query.
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_PIPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT helper stdout requires its original local byte pipe",
            ));
        }
        let mut mode = 0;
        // SAFETY: mode is one initialized output; optional outputs are null.
        if unsafe {
            GetNamedPipeHandleStateW(
                file.as_raw_handle(),
                &mut mode,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if mode & PIPE_READMODE_MESSAGE != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let nonblocking = mode | PIPE_NOWAIT;
        // SAFETY: changes only the owned original end, preserving its read mode.
        if unsafe {
            SetNamedPipeHandleState(
                file.as_raw_handle(),
                &nonblocking,
                std::ptr::null(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            mode: Mode::Nonblocking(mode),
        })
    }
    /// Query the original reader without bytes, PID lookup or replacement.
    /// QueryInformationFile is a synchronous API even for asynchronous file
    /// objects: its SDK outputs remain stack-owned until the call returns.
    /// See the [Windows synchronous-operation contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioisoperationsynchronous).
    #[expect(
        unsafe_code,
        reason = "Documented synchronous metadata API borrows initialized SDK records for the duration of the call only"
    )]
    pub fn state(&mut self) -> io::Result<State> {
        if matches!(self.mode, Mode::Closed) {
            return Ok(State::Closed);
        }
        // SAFETY: SDK records contain only integer/pointer fields; zero is valid.
        let (mut status, mut information): (IO_STATUS_BLOCK, FILE_PIPE_LOCAL_INFORMATION) =
            unsafe { std::mem::zeroed() };
        // SAFETY: original file and correctly sized outputs stay live until this
        // synchronous API completes, including on overlapped file objects.
        let result = unsafe {
            NtQueryInformationFile(
                self.file.as_raw_handle(),
                &mut status,
                (&mut information as *mut FILE_PIPE_LOCAL_INFORMATION).cast(),
                size_of::<FILE_PIPE_LOCAL_INFORMATION>() as u32,
                FilePipeLocalInformation,
            )
        };
        if result < 0 {
            // SAFETY: scalar NTSTATUS conversion has no ownership/memory effects.
            let error =
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32);
            if crate::pipe::is_peer_closed(&error) {
                self.mode = Mode::Closed;
                return Ok(State::Closed);
            }
            return Err(error);
        }
        if status.Information < size_of::<FILE_PIPE_LOCAL_INFORMATION>() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        match information.NamedPipeState {
            FILE_PIPE_CONNECTED_STATE => Ok(State::Connected),
            FILE_PIPE_DISCONNECTED_STATE | FILE_PIPE_CLOSING_STATE => {
                self.mode = Mode::Closed;
                Ok(State::Closed)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original helper output pipe is not connected",
            )),
        }
    }
    /// Attempt one nonblocking original write. A full byte pipe's zero progress
    /// is WouldBlock, never a successful endpoint line. Restoration fences writes.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !matches!(self.mode, Mode::Nonblocking(_)) || self.state()? == State::Closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        match self.file.write(bytes) {
            Ok(0) if !bytes.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            Err(error) if crate::pipe::is_peer_closed(&error) => {
                self.mode = Mode::Closed;
                Err(error)
            }
            result => result,
        }
    }
    /// Restore a still-live endpoint's original mode and close local admission.
    /// A physically closed reader is terminal and cannot create another generation.
    #[expect(
        unsafe_code,
        reason = "Restores the captured scalar mode on the same retained pipe end"
    )]
    pub fn restore(&mut self) -> io::Result<()> {
        if let Mode::Nonblocking(mode) = self.mode {
            // SAFETY: original file and its captured initialized mode remain live.
            if unsafe {
                SetNamedPipeHandleState(
                    self.file.as_raw_handle(),
                    &mode,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            self.mode = Mode::Restored;
        }
        Ok(())
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        let _restored = self.restore();
    }
}
