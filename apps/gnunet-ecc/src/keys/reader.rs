//! Exact raw32 records from one held native file and selected directory.
use super::namespace::{Namespace, observe};
use crate::{
    Failure,
    run::{Facts, Guard},
};
use gnunet_native::filesystem::{EntryInfo, FileInfo};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub(super) struct Reader {
    file: File,
    namespace: Namespace,
    original: FileInfo,
    pub(super) rows: u64,
}
impl Reader {
    pub(super) fn open(path: &Path) -> Result<Self, Failure> {
        let namespace = Namespace::select(path)?;
        let file = namespace.directory.open_file(&namespace.name)?;
        let original = observe(&file)?;
        if namespace.directory.entry_info(&namespace.name)? != EntryInfo::File(original) {
            return Err("ECC key input is not the original regular file".into());
        }
        if original.bytes == 0 || original.bytes % 32 != 0 {
            return Err("ECC key input must contain complete nonempty raw32 records".into());
        }
        let result = Self {
            file,
            namespace,
            original,
            rows: original.bytes / 32,
        };
        result.verify()?;
        Ok(result)
    }
    pub(super) fn verify(&self) -> Result<(), Failure> {
        self.namespace.verify()?;
        if observe(&self.file)? != self.original
            || self.namespace.directory.entry_info(&self.namespace.name)?
                != EntryInfo::File(self.original)
        {
            return Err("original ECC key file changed during observation".into());
        }
        Ok(())
    }
    pub(super) async fn record(
        &mut self,
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<Zeroizing<[u8; 32]>, Failure> {
        guard.check().await?;
        self.verify()?;
        guard.check().await?;
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut at = 0;
        while at < seed.len() {
            guard.check().await?;
            match self.file.read(&mut seed[at..]) {
                Ok(0) => return Err("original ECC raw32 record ended prematurely".into()),
                Ok(n) => {
                    at += n;
                    if at == seed.len() {
                        facts.records_read = facts
                            .records_read
                            .checked_add(1)
                            .ok_or("ECC input record count overflow")?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
            guard.check().await?;
        }
        self.verify()?;
        guard.check().await?;
        Ok(seed)
    }
}
