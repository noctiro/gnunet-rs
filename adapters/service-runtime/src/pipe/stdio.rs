//! Process stdio registered with the native I/O completion reactor.
use std::{
    io,
    task::{Context, Poll},
};
use tokio::net::windows::named_pipe::NamedPipeServer;
/// Original overlapped helper-output reader paired with a synchronous writer.
/// Its handle is never inherited by the helper, so closing it ends that output
/// generation even if a process identifier has been reused.
#[derive(Debug)]
pub struct OutputReader(NamedPipeServer);
impl OutputReader {
    /// Register only a freshly qualified native output reader in this runtime.
    /// Call under an entered Tokio runtime with I/O enabled. A runtime without
    /// I/O can panic during reactor registration.
    #[expect(
        unsafe_code,
        reason = "The native constructor qualifies a connected overlapped server and transfers its original handle once"
    )]
    pub fn new(handle: gnunet_native::pipe::OutputReadHandle) -> io::Result<Self> {
        use std::os::windows::io::IntoRawHandle;
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let handle = handle.into_handle().into_raw_handle();
        // SAFETY: native qualification guarantees the original connected server
        // has FILE_FLAG_OVERLAPPED. Tokio adopts it, including on registration error.
        unsafe { NamedPipeServer::from_raw_handle(handle) }.map(Self)
    }
}
impl tokio::io::AsyncRead for OutputReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
    }
}

/// Original overlapped parent writer paired with synchronous child stdin.
/// Writes report local transport acceptance. Flush/shutdown does not prove
/// overlapped completion, child consumption or application processing.
#[derive(Debug)]
pub struct InputWriter(NamedPipeServer);
impl InputWriter {
    /// Register a freshly qualified native stdin writer with the current reactor.
    /// Requires an entered Tokio runtime with I/O enabled; missing I/O can panic.
    #[expect(
        unsafe_code,
        reason = "Native qualification transfers a connected overlapped server once into Tokio ownership"
    )]
    pub fn new(handle: gnunet_native::pipe::InputWriteHandle) -> io::Result<Self> {
        use std::os::windows::io::IntoRawHandle;
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let handle = handle.into_handle().into_raw_handle();
        // SAFETY: qualified connected overlapped server is adopted even on error.
        unsafe { NamedPipeServer::from_raw_handle(handle) }.map(Self)
    }
}
impl tokio::io::AsyncWrite for InputWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
