//! Official nonpersistent counters, independent of transport write acknowledgements.
use super::*;
/// A point-in-time diagnostic snapshot. Counters saturate without refusing work;
/// gauges are the original current runtime inventory, never recovered history.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Actual accepted live handles, including those before CONNECTION_CREATE.
    pub handles_connected: u64,
    /// Successful OPEN operations; repeated OPEN on an active lease also counts.
    pub room_openings: u64,
    /// Successful ENTRY operations; repeated ENTRY on an active lease also counts.
    pub room_entries: u64,
    /// Successful release of an established handle-room lease, including disconnect.
    pub room_closings: u64,
    /// Distinct live rooms with an established local handle-room lease.
    pub rooms_active: u64,
    /// Completed service fanout invocations, once each even with no recipients.
    pub message_notifications: u64,
}
impl Statistics {
    pub(super) fn opened(&mut self, entry: bool) {
        let n = if entry {
            &mut self.room_entries
        } else {
            &mut self.room_openings
        };
        *n = n.saturating_add(1);
    }
    pub(super) fn closed_room(&mut self) {
        self.room_closings = self.room_closings.saturating_add(1);
    }
    pub(super) fn notified(&mut self) {
        self.message_notifications = self.message_notifications.saturating_add(1);
    }
}
impl<E: Entropy, const O: usize> Server<'_, '_, '_, E, O> {
    /// Read real local facts. This grants no operation, delivery or durability receipt.
    #[must_use]
    pub fn statistics(&self) -> Statistics {
        let mut observed = self.statistics;
        observed.handles_connected =
            u64::try_from(self.apps.iter().flatten().count()).unwrap_or(u64::MAX);
        observed.rooms_active = u64::try_from(
            self.rooms
                .iter()
                .flatten()
                .filter(|room| {
                    self.apps.iter().flatten().any(|app| {
                        app.rooms
                            .iter()
                            .any(|lease| lease.room == room.room && lease.counted)
                    })
                })
                .count(),
        )
        .unwrap_or(u64::MAX);
        observed
    }
}
