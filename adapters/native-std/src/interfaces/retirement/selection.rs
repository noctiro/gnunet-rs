//! Pure full-identity selection over an already complete native table.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Key {
    pub luid: u64,
    pub index: u32,
    pub guid: [u8; 16],
}
/// Actual selection of the old LUID in a complete native interface table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfacePresence {
    /// Original LUID, GUID and index still match.
    Present,
    /// No current interface has the original LUID. Route absence is separate.
    Missing,
    /// That LUID belongs to a different GUID or index; never delete its routes.
    Reused,
}
pub(super) fn classify(original: Key, rows: impl Iterator<Item = Key>) -> InterfacePresence {
    let mut result = InterfacePresence::Missing;
    for row in rows {
        if row.luid == original.luid {
            if row != original {
                result = InterfacePresence::Reused;
            } else if result != InterfacePresence::Reused {
                result = InterfacePresence::Present;
            }
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_reuse_never_becomes_original_presence_in_either_order() {
        let original = Key {
            luid: 19,
            index: 3,
            guid: [1; 16],
        };
        let reused = Key {
            guid: [2; 16],
            ..original
        };
        assert_eq!(
            classify(original, [original, reused].into_iter()),
            InterfacePresence::Reused
        );
        assert_eq!(
            classify(original, [reused, original].into_iter()),
            InterfacePresence::Reused
        );
        assert_eq!(
            classify(
                original,
                [Key {
                    index: 4,
                    ..original
                }]
                .into_iter()
            ),
            InterfacePresence::Reused
        );
    }
    #[test]
    fn same_logical_guid_cannot_rebind_the_original_physical_luid() {
        let original = Key {
            luid: 19,
            index: 3,
            guid: [1; 16],
        };
        let replacement = Key {
            luid: 20,
            index: 4,
            ..original
        };
        assert_eq!(
            classify(original, [replacement].into_iter()),
            InterfacePresence::Missing
        );
        assert_eq!(
            classify(original, [original].into_iter()),
            InterfacePresence::Present
        );
    }
}
