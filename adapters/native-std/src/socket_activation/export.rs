//! Parent publication of original listener records for one pinned child.
use super::{
    mapping::Writable,
    record::{HEADER, MAGIC, RECORD, VERSION, ensure_winsock, extent, socket_error},
};
use crate::process::{Process, ProcessIdentity};
use std::{
    error::Error,
    fmt, io,
    os::windows::io::{AsHandle, AsRawSocket, BorrowedHandle, BorrowedSocket},
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::Networking::WinSock::{
    SOCKET_ERROR, WSADuplicateSocketW, WSAPROTOCOL_INFOW,
};
/// Writable anonymous section, exported to a suspended child using only its
/// read-only handle. No public method exposes the writable view or handle.
pub struct ExportSection {
    mapping: Writable,
    count: usize,
}
impl fmt::Debug for ExportSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportSection")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl AsHandle for ExportSection {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.mapping.read.as_handle()
    }
}
/// Native metadata publication, not target import or service readiness.
#[derive(Debug)]
pub struct Publication {
    _target: ProcessIdentity,
    count: usize,
}
impl Publication {
    /// Number of successful native listener exports in this sealed section.
    pub fn len(&self) -> usize {
        self.count
    }
    /// Whether this publication carries no listeners.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
/// Failed publication preserves its mapping cleanup owner and actual export
/// progress. Successful SDK exports remain target-owned debt until import or
/// target exit; closing this mapping does not cancel those provider resources.
pub struct PublishFailure {
    /// Original native/setup/view-retirement error.
    pub error: io::Error,
    /// Number of successful WSADuplicateSocket calls, never an import receipt.
    pub exported: usize,
    _target: ProcessIdentity,
    section: ExportSection,
}
impl PublishFailure {
    /// Retry only original view retirement. This cannot republish/replay tickets
    /// or settle target-side resources; explicitly retire/drain the failed child.
    pub fn close_view(&mut self) -> io::Result<()> {
        self.section.mapping.view.close()
    }
}
impl fmt::Debug for PublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishFailure")
            .field("error", &self.error)
            .field("exported", &self.exported)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl Error for PublishFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}
impl ExportSection {
    /// Allocate zeroed pagefile storage and a noninheritable read-only handle
    /// before native process admission. Export only `as_handle` to the child.
    pub fn new(count: usize) -> io::Result<Self> {
        Ok(Self {
            mapping: Writable::new(extent(count)?)?,
            count,
        })
    }
    /// Publish exact listener order for this original suspended target, then
    /// retire all parent writable access. Caller excludes external resume and
    /// concurrent socket I/O/options/registration. Sources must be overlapped
    /// listeners never attached to an IOCP or event-selection registration.
    /// Keep source descriptors alive until target reconstruction is confirmed.
    /// On failure the target must not be resumed: terminate/drain it to settle
    /// any provider-side exports. No raw PID reconstruction is performed here.
    #[expect(
        unsafe_code,
        reason = "WSADuplicateSocketW writes exact aligned initialized record storage for a pinned original process; a release publication precedes writable-view retirement and child resume"
    )]
    pub fn publish(
        mut self,
        target: &Process,
        sockets: &[BorrowedSocket<'_>],
    ) -> Result<Publication, PublishFailure> {
        let mut exported = 0;
        let result = (|| {
            if sockets.len() != self.count {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            ensure_winsock()?;
            let pointer = self.mapping.view.pointer_mut();
            for socket in sockets {
                // SAFETY: each exact record lies in the bounded zeroed view;
                // HEADER/RECORD are four-byte aligned and the original target's
                // process owner pins its native PID throughout this operation.
                let output = unsafe {
                    pointer
                        .add(HEADER + exported * RECORD)
                        .cast::<WSAPROTOCOL_INFOW>()
                };
                // SAFETY: live borrowed socket, original target, exact writable output.
                if unsafe {
                    WSADuplicateSocketW(socket.as_raw_socket() as usize, target.id(), output)
                } == SOCKET_ERROR
                {
                    return Err(socket_error());
                }
                exported += 1;
            }
            let values = [
                VERSION,
                self.count as u32,
                RECORD as u32,
                target.id(),
                extent(self.count)? as u32,
                0,
                0,
            ];
            for (index, value) in values.into_iter().enumerate() {
                // SAFETY: fixed header words all lie before the record area.
                unsafe { pointer.add(4 + index * 4).cast::<u32>().write(value) };
            }
            // SAFETY: page-aligned zeroed storage supports an AtomicU32. All
            // record/header writes precede this sole release publication.
            unsafe { &*pointer.cast::<AtomicU32>() }.store(MAGIC, Ordering::Release);
            self.mapping.view.close()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Publication {
                _target: target.identity(),
                count: self.count,
            }),
            Err(error) => Err(PublishFailure {
                error,
                exported,
                _target: target.identity(),
                section: self,
            }),
        }
    }
}
