use gnunet_arm_core::{client::Client,wire::{ArmAbi,List},FrameTicket};
use gnunet_types::Error;
pub fn received<'a>(rx:&'a[u8])->Result<List<'a>,Error>{List::decode(ArmAbi::U64Align8,rx)}
pub fn after_actual_full_write(owner:&mut Client<'_>,ticket:FrameTicket)->Result<usize,Error>{
 let n=owner.frame(ticket)?.len();
 owner.frame_written(ticket)?;
 Ok(n)
}
