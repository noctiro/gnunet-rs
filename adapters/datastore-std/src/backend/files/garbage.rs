//! Incremental, original-directory enumeration with a caller-supplied work bound.
use super::{Error, Files, ProtocolError, object::parse_object, temporary::is_temporary};
use gnunet_native::filesystem::private_single_file_identity;
impl Files {
    pub(in super::super) fn reset_garbage(&mut self) {
        self.garbage = None;
        self.garbage_root = None;
        self.garbage_values_done = false;
    }
    pub(in super::super) fn collect_orphans(
        &mut self,
        live: impl Fn(u64) -> bool,
        maximum: usize,
    ) -> Result<(usize, bool), Error> {
        if maximum == 0 {
            return Err(Error::protocol(
                "garbage-budget",
                ProtocolError::InvalidInput,
            ));
        }
        let mut removed = 0;
        for _ in 0..maximum {
            let in_values = !self.garbage_values_done;
            if in_values && self.garbage.is_none() {
                self.garbage = Some(
                    self.values
                        .entries()
                        .map_err(|e| Error::io("garbage-directory", e))?,
                );
            }
            if !in_values && self.garbage_root.is_none() {
                self.garbage_root = Some(
                    self.root
                        .entries()
                        .map_err(|e| Error::io("garbage-root-directory", e))?,
                );
            }
            let next = if in_values {
                self.garbage.as_mut().and_then(Iterator::next)
            } else {
                self.garbage_root.as_mut().and_then(Iterator::next)
            };
            let Some(name) = next else {
                if in_values {
                    self.garbage = None;
                    self.garbage_values_done = true;
                    continue;
                }
                self.garbage_root = None;
                self.garbage_values_done = false;
                if removed != 0 || self.directory_sync().is_none() {
                    self.sync_names()?;
                }
                return Ok((removed, false));
            };
            let name = name.map_err(|e| Error::io("garbage-entry", e))?;
            // Only ASCII internal names are recognized on every platform.
            let raw = name.as_encoded_bytes();
            if in_values && let Some(uid) = parse_object(raw) {
                if !live(uid) && self.remove_unreferenced(uid)? {
                    removed += 1;
                }
            } else if is_temporary(raw) {
                let directory = if in_values { &self.values } else { &self.root };
                let file = directory
                    .open_file(&name)
                    .map_err(|e| Error::io("stale-temporary-open", e))?;
                private_single_file_identity(&file)
                    .map_err(|e| Error::io("stale-temporary-metadata", e))?;
                if in_values {
                    self.names.values = None;
                } else {
                    self.names.root = None;
                }
                directory
                    .remove_file(&name, &file)
                    .map_err(|e| Error::io("stale-temporary-remove", e))?;
                removed += 1;
            }
        }
        if removed != 0 || self.directory_sync().is_none() {
            self.sync_names()?;
        }
        Ok((removed, true))
    }
}
