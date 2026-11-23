//! Canonical WFP identifiers shared with the WDK callout build.

/// Static provider identity for the driver callout metadata.
pub const DRIVER_PROVIDER: u128 = 0x61a7c026_25d2_4f98_b801_8ebf06c991bd;
/// Original IPv4 flow discovery callout.
pub const FLOW_V4: u128 = 0x75db8ba8_713c_4e6f_b962_5cf3640516d1;
/// Original IPv6 flow discovery callout.
pub const FLOW_V6: u128 = 0x63728664_cbe6_45a9_839d_5f1b12bf3520;
/// Original IPv4 datagram callout.
pub const DATAGRAM_V4: u128 = 0xb37ab8b0_0f82_40f6_a432_c7df2a823507;
/// Original IPv6 datagram callout.
pub const DATAGRAM_V6: u128 = 0x0d49ab2f_3049_4320_81a2_1840e0d1c524;
/// Original IPv4 ALE endpoint-closure callout.
pub const CLOSURE_V4: u128 = 0xc14f422a_5c60_4590_a828_a55d61d36b7f;
/// Original IPv6 ALE endpoint-closure callout.
pub const CLOSURE_V6: u128 = 0x5bb27602_4c22_4a8a_a8e5_7018cbe725f7;
/// Independent receive guard provider.
pub const GUARD_PROVIDER: u128 = 0x4088277a_bce4_49e6_afbc_b73f907ef8e5;
/// Independent receive guard sublayer.
pub const GUARD_SUBLAYER: u128 = 0xde53329a_fe24_48c1_80b3_edca7a0f1b77;
/// All-inbound-UDP IPv4 guard.
pub const GUARD_V4: u128 = 0xd1863502_0a58_41fe_a89e_657be1e4564c;
/// All-inbound-UDP IPv6 guard.
pub const GUARD_V6: u128 = 0x76678afa_bbfe_48a9_859d_6f99dd6b6208;
