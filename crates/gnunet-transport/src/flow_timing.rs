use core::time::Duration;
use gnunet_wire::official::communicator::DEFAULT_PEER_IDLE_TIMEOUT;

// Match the reference retransmit floor and send idle keepalives before the
// communicator can retire its connection. Both FLOW engines use microseconds.
pub(crate) const MIN_MICROS: u64 = Duration::from_millis(100).as_micros() as u64;
pub(crate) const KEEPALIVE_MICROS: u64 = DEFAULT_PEER_IDLE_TIMEOUT.as_micros() as u64 / 2;
