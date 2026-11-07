use gnunet_arm_core::wire::ArmAbi;
use gnunet_arm_service_core::*;
pub fn invalid() {
    let mut scope = OwnerScope::new();
    let specs = [];
    let mut services = [];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [];
    let mut data = [0; 64];
    let mut frames = [FrameSlot::new(&mut data)];
    let mut original = Owner::new(
        &mut scope,
        &specs,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .unwrap();
    original.startup_next().unwrap();
    let old_token = original.connect().unwrap();
    drop(original);
    let mut replacement = Owner::new(
        &mut scope,
        &specs,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .unwrap();
    replacement.startup_next().unwrap();
    let _result = replacement.test(old_token);
}
