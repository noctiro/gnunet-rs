//! One controlled datagram-FD ownership model. It is not a real TUN qualification.
use super::*;
use std::{error::Error, os::unix::net::UnixDatagram, time::Duration};
use tokio::time::Instant;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Checks actual controlled-FD packet boundaries and original cancellation without creating any TUN device"
)]
fn controlled_fd_preserves_packet_owner_without_claiming_tun() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let (left,right)=UnixDatagram::pair()?;
        let info=Info{name:"controlled-model".to_owned(),index:0,mode:Mode::Utun};
        // Private constructor bypasses device qualification only inside this
        // internal model; the public from_fd still requires actual kernel proof.
        let owned=OwnedTun::verified(left.into(),info,Limits{packet_bytes:1400})?;
        let mut tun=AsyncTun::new(owned)?;
        let original=tun.epoch();
        let until=Instant::now()+Duration::from_secs(1);
        let mut raw=[0u8;40];raw[0]=0x60;raw[6]=59;raw[7]=64;
        let id=tun.queue(&raw,until)?;
        drop(tun.write(until)); // Dropping an unpolled future retains this packet.
        assert!(matches!(tun.write(until).await,WriteEvent::Written{write,raw_bytes:40}if write==id));
        let mut native=[0u8;64];let n=right.recv(&mut native)?;
        assert_eq!(&native[..4],&[0,0,0,30]);assert_eq!(&native[4..n],&raw);
        assert_eq!(right.send(&native[..n])?,n);
        match tun.read(until).await{ReadEvent::Packet(packet)=>{assert_eq!(packet.epoch(),&original);assert_eq!(packet.version(),Version::V6);assert_eq!(packet.bytes(),&raw);assert_eq!(packet.native_bytes(),&native[..n]);},_=>return Err("controlled packet observation missing".into())}
        let cancelled=tun.queue(&raw,until)?;
        assert!(matches!(tun.cancel(&cancelled)?,WriteEvent::Unsent{write,reason:Unsent::Cancelled}if write==cancelled));
        let effect=tun.plan(Action::Route{add:true,destination:std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),prefix:128,gateway:None},until)?;
        let loss=tun.close();assert!(loss.close_error.is_none());assert!(!original.current());
        let report=effect.report(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        assert_eq!(report.timing,Timing::SourceRetired);assert_eq!(report.outcome.err().and_then(|e|e.raw_os_error()),Some(libc::EPERM));
        // A real socket cannot pass the public TUN/utun qualification path.
        assert!(OwnedTun::from_fd(right.into(),Limits::default()).is_err());
        Ok::<(),Box<dyn Error>>(())
    })
}
