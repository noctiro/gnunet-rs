//! Qualified parent-overlapped/child-synchronous process byte pipes.
use crate::{identity::PrivateSecurityDescriptor, pipe::Endpoint};
use std::{
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, OwnedHandle},
    },
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
        OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    },
    System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};
mod write;
pub use write::InputWriter;
/// Connected overlapped parent reader, never inherited by the child.
#[derive(Debug)]
pub struct OutputReadHandle(OwnedHandle);
impl OutputReadHandle {
    /// Transfer the qualified original handle once for reactor registration.
    pub fn into_handle(self) -> OwnedHandle {
        self.0
    }
}
/// Connected overlapped parent writer, never inherited by the child.
#[derive(Debug)]
pub struct InputWriteHandle(OwnedHandle);
impl InputWriteHandle {
    /// Transfer the qualified original handle once for reactor registration.
    pub fn into_handle(self) -> OwnedHandle {
        self.0
    }
}
/// Create child stdout and parent reader before child creation. The synchronous
/// writer can observe original-reader closure through read-attribute rights.
/// Neither handle is inheritable; launch duplicates only the selected child end.
/// Caller excludes thread impersonation during security preparation.
pub fn output_pair() -> io::Result<(OutputReadHandle, File)> {
    let (parent, child) = pair(Direction::Output)?;
    Ok((OutputReadHandle(parent), child))
}
/// Create child stdin and parent writer before child creation. The child receives
/// a synchronous reader through explicit stdio duplication. No blocking worker,
/// overlapped connect, protocol probe or remote pipe endpoint is created.
/// Caller excludes thread impersonation during security preparation.
pub fn input_pair() -> io::Result<(InputWriteHandle, File)> {
    let (parent, child) = pair(Direction::Input)?;
    Ok((InputWriteHandle(parent), child))
}
#[derive(Clone, Copy)]
enum Direction {
    Input,
    Output,
}
#[expect(
    unsafe_code,
    reason = "SDK constructors borrow initialized names/security and return fresh handles adopted once"
)]
fn pair(direction: Direction) -> io::Result<(OwnedHandle, File)> {
    let endpoint = Endpoint::generate()?;
    let name: Vec<u16> = endpoint.as_os_str().encode_wide().chain(Some(0)).collect();
    let descriptor = PrivateSecurityDescriptor::owner_only()?;
    let mut attributes = descriptor.attributes();
    let (access, child_access) = match direction {
        Direction::Output => (PIPE_ACCESS_INBOUND, GENERIC_WRITE | FILE_READ_ATTRIBUTES),
        Direction::Input => (PIPE_ACCESS_OUTBOUND, GENERIC_READ),
    };
    // SAFETY: terminated name and protected noninheritable attributes remain live.
    let parent = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            access | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            attributes.as_mut_ptr().cast(),
        )
    };
    if parent == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful construction returned a fresh original server handle.
    let parent = unsafe { OwnedHandle::from_raw_handle(parent) };
    // Opening this first instance connects it without a pending ConnectNamedPipe.
    // SAFETY: null security attributes prevent child-end inheritance by default.
    let child = unsafe {
        CreateFileW(
            name.as_ptr(),
            child_access,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if child == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful construction returned one fresh synchronous client.
    let child = unsafe { OwnedHandle::from_raw_handle(child) };
    Ok((parent, File::from(child)))
}
