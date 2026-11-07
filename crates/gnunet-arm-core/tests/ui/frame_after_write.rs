use gnunet_arm_core::{client::Client,FrameTicket};
use gnunet_types::Error;
pub fn invalid(owner:&mut Client<'_>,ticket:FrameTicket)->Result<(),Error>{
 let frame=owner.frame(ticket)?;
 owner.frame_written(ticket)?;
 assert!(!frame.is_empty());
 Ok(())
}
