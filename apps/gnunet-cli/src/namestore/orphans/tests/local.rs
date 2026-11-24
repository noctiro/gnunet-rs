//! Windows AF_UNIX fixture peers over original Winsock owners.
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io::{self, Read, Write},
    path::Path,
};
pub(super) struct Listener(Socket);
pub(super) struct Stream(Socket);
impl Listener {
    pub(super) fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(path)?)?;
        socket.listen(16)?;
        Ok(Self(socket))
    }
    pub(super) fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.0.set_nonblocking(value)
    }
    pub(super) fn accept(&self) -> io::Result<(Stream, SockAddr)> {
        let (socket, address) = self.0.accept()?;
        Ok((Stream(socket), address))
    }
}
impl Stream {
    pub(super) fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.0.set_nonblocking(value)
    }
}
impl Read for Stream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output)
    }
}
impl Write for Stream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0.write(input)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
