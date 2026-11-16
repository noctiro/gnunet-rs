//! One bounded native session; driver packet loans never escape a method call.
use super::{Adapter, Driver, MAX_PACKET_BYTES, RingCapacity};
use std::{ffi::c_void, io, os::windows::io::BorrowedHandle, ptr::NonNull};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, INVALID_HANDLE_VALUE,
};
/// Actual local receive outcome, without checksum, route or peer assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Receive {
    /// The original ring had no packet; the session remains live.
    Empty,
    /// One complete packet was copied and its original native loan released.
    Packet(usize),
    /// The consumed original packet exceeded the caller's capacity. No truncated
    /// bytes were delivered, and the original loan was released exactly once.
    Discarded {
        /// Actual original packet extent.
        packet_bytes: usize,
        /// Caller-provided output capacity.
        capacity: usize,
    },
}
/// Actual local send-ring result; neither variant proves network transmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendStatus {
    /// The original complete packet was submitted to the provider's send ring.
    Queued,
    /// No packet was allocated; the caller retains its original unchanged bytes.
    Full,
}
/// Start refusal preserves the original adapter and its removal responsibility.
#[derive(Debug)]
pub struct StartError {
    adapter: Adapter,
    error: io::Error,
}
impl StartError {
    /// Recover the original adapter and actual native/setup failure.
    pub fn into_parts(self) -> (Adapter, io::Error) {
        (self.adapter, self.error)
    }
}
impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wintun session start: {}", self.error)
    }
}
impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// One session and its unique original adapter. No packet queue, worker, runtime
/// or callback is created here. Drop ends the session before closing the adapter.
pub struct Session {
    // Field order also covers ordinary Drop: session retirement precedes adapter.
    native: NativeSession,
    adapter: Adapter,
    capacity: RingCapacity,
    kind: SessionKind,
}
struct NativeSession {
    raw: NonNull<c_void>,
    driver: Driver,
}
/// Session admission history on this exact adapter owner; opening another
/// adapter does not inherit another owner's configuration/removal authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionKind {
    /// First successfully admitted session on this adapter owner.
    First,
    /// A preceding session ended while retaining this same original adapter.
    Restarted,
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("ring_capacity", &self.capacity)
            .field("adapter", &self.adapter)
            .field("kind", &self.kind)
            .finish()
    }
}
impl Adapter {
    /// Start one fixed-capacity session, transferring this adapter's lifetime.
    #[expect(
        unsafe_code,
        reason = "The exact trusted export borrows one original adapter and transfers a new original session handle on success"
    )]
    pub fn start(mut self, capacity: RingCapacity) -> Result<Session, StartError> {
        if let Err(error) = self.identity.row() {
            return Err(StartError {
                adapter: self,
                error,
            });
        }
        let adapter = self.owners.packet.raw;
        // SAFETY: original adapter and DLL stay owned; capacity was validated.
        let raw =
            unsafe { (self.owners.packet.driver.0.start)(adapter.as_ptr(), capacity.bytes()) };
        let Some(raw) = NonNull::new(raw) else {
            let error = io::Error::last_os_error();
            return Err(StartError {
                adapter: self,
                error,
            });
        };
        let kind = self.next_session;
        self.next_session = SessionKind::Restarted;
        let native = NativeSession {
            raw,
            driver: self.owners.packet.driver.clone(),
        };
        if let Err(error) = self.identity.row() {
            // A real native admission happened, but its original physical
            // identity no longer qualifies. End those rings before returning
            // the same adapter; never publish an unqualified session.
            drop(native);
            return Err(StartError {
                adapter: self,
                error,
            });
        }
        Ok(Session {
            native,
            adapter: self,
            capacity,
            kind,
        })
    }
}
struct Packet<'a> {
    session: NonNull<c_void>,
    api: &'a super::api::Api,
    raw: NonNull<u8>,
}
impl Drop for Packet<'_> {
    #[expect(
        unsafe_code,
        reason = "Each successful ReceivePacket creates exactly one guard; the original session/DLL borrow outlives its matching release"
    )]
    fn drop(&mut self) {
        // SAFETY: exact original loan/session and retained DLL. The private
        // guard is linear and never outlives the borrowing receive method.
        unsafe { (self.api.release)(self.session.as_ptr(), self.raw.as_ptr()) };
    }
}
impl Session {
    /// Original adapter metadata/removal responsibility, without raw handle access.
    pub const fn adapter(&self) -> &Adapter {
        &self.adapter
    }
    /// Fixed native bytes per receive/send ring.
    pub const fn capacity(&self) -> RingCapacity {
        self.capacity
    }
    /// Whether this original adapter has already hosted a retired session.
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }
    /// Borrow the provider-owned read event. The session retains and closes it;
    /// callers must not reset, duplicate ownership of or close this event. A
    /// signal is only permission to try receive, never a packet/completion proof.
    #[expect(
        unsafe_code,
        reason = "The provider returns its live session-owned event; the borrowed lifetime is tied to this session and never owns CloseHandle"
    )]
    pub fn read_event(&self) -> io::Result<BorrowedHandle<'_>> {
        let session = self.native.raw;
        // SAFETY: original session and provider outlive the returned borrow.
        let event = unsafe { (self.adapter.owners.packet.driver.0.event)(session.as_ptr()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wintun returned no original read event",
            ));
        }
        // SAFETY: borrowed original provider event; never transferred to Drop.
        Ok(unsafe { BorrowedHandle::borrow_raw(event) })
    }
    /// Make one zero-timeout observation of the original provider read event.
    /// This creates no watcher/worker and consumes no packet. Pending callers
    /// must arrange their own native wait; a true result is not a read receipt.
    #[expect(
        unsafe_code,
        reason = "WaitForSingleObject borrows the original session-owned event for one zero-timeout observation; no handle ownership is transferred"
    )]
    pub fn receive_ready(&self) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };
        let event = self.read_event()?;
        // SAFETY: original event remains borrowed through this nonblocking wait.
        match unsafe { WaitForSingleObject(event.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected Wintun event wait result",
            )),
        }
    }
    /// Attempt one complete receive. Empty consumes no packet. Oversize drops
    /// exactly that original loan; no truncated bytes are exposed. Packet bytes
    /// remain unverified IP input for the domain parser.
    #[expect(
        unsafe_code,
        reason = "The exact trusted API loans PacketSize readable bytes until release; bounds precede copying into an exclusive caller slice and the guard releases every path"
    )]
    pub fn receive(&self, output: &mut [u8]) -> io::Result<Receive> {
        let session = self.native.raw;
        let mut length = 0_u32;
        // SAFETY: exact original session and writable DWORD output remain live.
        let raw =
            unsafe { (self.adapter.owners.packet.driver.0.receive)(session.as_ptr(), &mut length) };
        let Some(raw) = NonNull::new(raw) else {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                Ok(Receive::Empty)
            } else {
                Err(error)
            };
        };
        let packet = Packet {
            session,
            api: &self.adapter.owners.packet.driver.0,
            raw,
        };
        let length = length as usize;
        if length > MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wintun packet exceeds native bound",
            ));
        }
        if length > output.len() {
            return Ok(Receive::Discarded {
                packet_bytes: length,
                capacity: output.len(),
            });
        }
        // SAFETY: trusted provider loans exactly length bytes; original packet
        // remains guarded and the exclusive caller slice cannot alias its ring.
        unsafe { std::ptr::copy_nonoverlapping(packet.raw.as_ptr(), output.as_mut_ptr(), length) };
        Ok(Receive::Packet(length))
    }
    /// Allocate/copy/submit one complete original packet without retaining a
    /// native loan across calls. Full is zero admission; Queued is provider-ring
    /// submission and does not imply transmission or remote processing.
    #[expect(
        unsafe_code,
        reason = "Bounds precede exact native allocation; one exclusive original send loan is initialized completely and submitted exactly once before returning"
    )]
    pub fn send(&self, packet: &[u8]) -> io::Result<SendStatus> {
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Wintun packet extent",
            ));
        }
        let session = self.native.raw;
        // SAFETY: bounded exact allocation on the original live session.
        let output = unsafe {
            (self.adapter.owners.packet.driver.0.allocate)(session.as_ptr(), packet.len() as u32)
        };
        let Some(output) = NonNull::new(output) else {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) {
                Ok(SendStatus::Full)
            } else {
                Err(error)
            };
        };
        // SAFETY: exact exclusive allocation; no pointer or native packet loan
        // escapes, and no fallible operation occurs between copy and submission.
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), output.as_ptr(), packet.len());
            (self.adapter.owners.packet.driver.0.send)(session.as_ptr(), output.as_ptr());
        }
        Ok(SendStatus::Queued)
    }
    /// End the original session once, then release its adapter. Both native
    /// functions return void, so this is no kernel-cleanup acknowledgement.
    pub fn close(self) {
        drop(self);
    }
    /// End this original session once and return its original adapter. Read-event
    /// registrations and borrowed packet operations must retire first. Adapter
    /// ownership, identity and removal responsibility are preserved; the void
    /// native return does not establish packet delivery or kernel removal.
    pub fn end(self) -> Adapter {
        let Self {
            native, adapter, ..
        } = self;
        drop(native);
        adapter
    }
}
impl Drop for NativeSession {
    #[expect(
        unsafe_code,
        reason = "The unique linear session is dropped once, before its adapter and DLL; no native packet or read-event borrow can outlive it"
    )]
    fn drop(&mut self) {
        // SAFETY: sole original session; all packet/event borrows have ended,
        // and automatic field Drop releases its adapter only after this call.
        unsafe { (self.driver.0.end)(self.raw.as_ptr()) };
    }
}
