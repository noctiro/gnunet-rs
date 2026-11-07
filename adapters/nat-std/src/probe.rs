//! Actual dedicated-socket external-IP STUN probe. The application's existing
//! transport socket is never taken over by this monitor.
use crate::{
    Error,
    deadline::{Bounds, Gate},
    stun::{Event, Limits, Request},
};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    task::Poll,
};
use tokio::{io::ReadBuf, net::UdpSocket};
/// Perform a real original bounded IPv4 STUN transaction, returning only the
/// server's matched mapped-address claim. It is not a remote reachability test.
pub async fn external_ipv4(
    resolver: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    server: Vec<u8>,
    port: u16,
    bounds: Bounds,
    max_datagrams: usize,
) -> Result<Ipv4Addr, Error> {
    if max_datagrams == 0 {
        return Err(Fault::InvalidInput.into());
    }
    let mut gate = Gate::new(clock.clone(), bounds)?;
    // One complete UDP payload fits without a truncated oversized datagram
    // masquerading as a shorter valid STUN response. Keep this out of the
    // future's inline storage and fail before creating a socket on allocation loss.
    let mut received = Vec::new();
    received
        .try_reserve_exact(65536)
        .map_err(|_| Fault::Capacity)?;
    received.resize(65536, 0);
    let socket = Arc::new(
        gate.run(UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))))
            .await?,
    );
    let mut request = Request::start(
        resolver,
        clock,
        socket.clone(),
        &server,
        port,
        bounds,
        Limits::default(),
    )?;
    let mut finished = false;
    let mut datagrams = 0usize;
    poll_fn(|cx| {
        match gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                request.cancel();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(_)) => {}
        }
        if !finished {
            match request.poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Event::Finished { written: 0, .. })) => {
                    return Poll::Ready(Err(Fault::NotFound.into()));
                }
                Poll::Ready(Ok(Event::Finished { .. })) => finished = true,
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        }
        if datagrams >= max_datagrams {
            return Poll::Ready(Err(Fault::Capacity.into()));
        }
        let mut read = ReadBuf::new(&mut received);
        match socket.poll_recv_from(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(sender)) => {
                datagrams += 1;
                match request.on_datagram(&socket, sender, read.filled()) {
                    Ok(Some(gnunet_nat::address::SocketAddress::V4 { ip, .. })) => {
                        Poll::Ready(Ok(Ipv4Addr::from(ip)))
                    }
                    Ok(_) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
        }
    })
    .await
}
