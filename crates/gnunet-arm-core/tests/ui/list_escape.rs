use gnunet_arm_core::wire::{ArmAbi,List};
use gnunet_types::Error;
pub fn escape<'a>() -> Result<List<'a>, Error> {
    let local = [0u8; 18];
    List::decode(ArmAbi::U64Align8,&local)
}
