//! Private per-query ciphertext files and the sole writer lease.
use gnunet_namecache::{Block, Cache, Limits};
use gnunet_native::filesystem::{
    Directory, ExclusiveFile, FileIdentity, private_single_file_identity, publication,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{AbsoluteTime, namecache::Request};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

const LOCK: &str = ".namecache-rust.lock";
const PREFIX: &str = "block-";

pub(super) struct Files {
    path: PathBuf,
    directory: Directory,
    directory_id: FileIdentity,
    lock: ExclusiveFile,
    block_bytes: usize,
}

pub(super) enum Mutation {
    Upsert { query: [u8; 64], block: Vec<u8> },
    Delete([u8; 64]),
}

fn filename(query: &[u8; 64]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(PREFIX.len() + query.len() * 2);
    result.push_str(PREFIX);
    for &byte in query {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn is_stage(name: &str) -> bool {
    let Some((pid, sequence)) = name
        .strip_prefix(".gnunet-file-")
        .and_then(|name| name.strip_suffix(".new"))
        .and_then(|name| name.split_once('-'))
    else {
        return false;
    };
    pid.parse::<u32>().is_ok() && sequence.parse::<u64>().is_ok()
}

impl Mutation {
    fn prepare(cache: &Cache, input: &[u8], max_block_bytes: usize) -> Result<Option<Self>, Fault> {
        match Request::decode(input)? {
            Request::Cache { block, .. } if block.len() <= max_block_bytes => {
                let incoming = Block::decode(block)?;
                let query = incoming.query()?;
                if let Some(retained) = cache.lookup(&query)?
                    && (retained.expiration()? > incoming.expiration()?
                        || retained.as_bytes() == block)
                {
                    return Ok(None);
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(block.len())
                    .map_err(|_| Fault::Capacity)?;
                owned.extend_from_slice(block);
                Ok(Some(Self::Upsert {
                    query,
                    block: owned,
                }))
            }
            Request::Delete { query, .. } if cache.lookup(query)?.is_some() => {
                Ok(Some(Self::Delete(*query)))
            }
            _ => Ok(None),
        }
    }
}

impl Files {
    pub(super) fn open(
        path: &Path,
        limits: Limits,
        now: AbsoluteTime,
    ) -> Result<(Self, Cache), crate::server::Error> {
        let mut cache = Cache::new(limits)?;
        gnunet_service_runtime::private_parents(&path.join(LOCK))?;
        let directory = Directory::open(path)?;
        directory.validate_private()?;
        let directory_id = FileIdentity::of(directory.as_file())?;
        let path = fs::canonicalize(path)?;
        let lock_name = OsStr::new(LOCK);
        let lock = match directory.open_file_for_update(lock_name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                directory.create_private_file(lock_name)?
            }
            Err(error) => return Err(error.into()),
        };
        private_single_file_identity(&lock)?;
        let lock = ExclusiveFile::try_lock(lock).map_err(io::Error::from)?;
        let files = Self {
            path,
            directory,
            directory_id,
            lock,
            block_bytes: limits.block_bytes,
        };
        files.verify()?;
        let mut blocks = 0;
        let mut stage = None;
        let mut expired = Vec::new();
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(limits.block_bytes)
            .map_err(|_| Fault::Capacity)?;
        for entry in files.directory.entries()? {
            let name = entry?;
            if name == lock_name {
                continue;
            }
            let name = name.to_str().ok_or(Fault::Malformed)?;
            if is_stage(name) && stage.is_none() {
                stage = Some(OsString::from(name));
                continue;
            }
            if !name.starts_with(PREFIX) || name.len() != PREFIX.len() + 128 {
                return Err(Fault::Malformed.into());
            }
            blocks += 1;
            if blocks > limits.entries {
                return Err(Fault::Capacity.into());
            }
            let name = OsStr::new(name);
            let file = files.directory.open_file(name)?;
            private_single_file_identity(&file)?;
            let length = usize::try_from(file.metadata()?.len()).map_err(|_| Fault::TooLarge)?;
            if length > limits.block_bytes {
                return Err(Fault::TooLarge.into());
            }
            buffer.resize(length, 0);
            let mut reader = &file;
            reader.read_exact(&mut buffer)?;
            if reader.read(&mut [0])? != 0 || !files.directory.same_file(name, &file)? {
                return Err(Fault::Stale.into());
            }
            let block = Block::decode(&buffer)?;
            let query = block.query()?;
            if OsStr::new(&filename(&query)) != name {
                return Err(Fault::Malformed.into());
            }
            if block.expiration()? < now.as_micros() {
                expired.try_reserve(1).map_err(|_| Fault::Capacity)?;
                expired.push(query);
            } else {
                cache.insert(&buffer)?;
            }
        }
        if let Some(stage) = stage {
            files.remove(&stage)?;
        }
        for query in &expired {
            files.remove(OsStr::new(&filename(query)))?;
        }
        files.directory.sync()?;
        files.verify()?;
        Ok((files, cache))
    }

    fn verify(&self) -> io::Result<()> {
        let selected = Directory::open(&self.path)?;
        if FileIdentity::of(selected.as_file())? != self.directory_id
            || !self
                .directory
                .same_file(OsStr::new(LOCK), self.lock.as_file())?
        {
            return Err(io::Error::other(
                "original NAMECACHE storage authority changed",
            ));
        }
        self.directory.validate_private()
    }

    fn remove(&self, name: &OsStr) -> io::Result<()> {
        let file = self.directory.open_file(name)?;
        private_single_file_identity(&file)?;
        self.directory.remove_file(name, &file)
    }

    pub(super) fn prepare(&self, cache: &Cache, input: &[u8]) -> Result<Option<Mutation>, Fault> {
        Mutation::prepare(cache, input, self.block_bytes)
    }

    pub(super) fn commit(&self, change: &Mutation) -> io::Result<()> {
        match change {
            Mutation::Upsert { query, block } => {
                self.verify()?;
                publication::publish(
                    &self.directory,
                    OsStr::new(&filename(query)),
                    block,
                    publication::Destination::Replace,
                    || self.verify(),
                )
                .map_err(io::Error::other)?;
                self.verify()
            }
            Mutation::Delete(query) => self.remove_queries(std::slice::from_ref(query)),
        }
    }

    pub(super) fn remove_queries(&self, queries: &[[u8; 64]]) -> io::Result<()> {
        self.verify()?;
        for query in queries {
            self.remove(OsStr::new(&filename(query)))?;
        }
        self.directory.sync()?;
        self.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &[u8] =
        include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
    const ED_BLOCK: &[u8] =
        include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_recovery_keeps_current_queries_and_retires_expired_files()
    -> Result<(), crate::server::Error> {
        let parent = fs::canonicalize(std::env::temp_dir())?;
        let mut nonce = [0; 8];
        gnunet_native::entropy::fill(&mut nonce)?;
        let name = format!("nc-files-{:016x}", u64::from_ne_bytes(nonce));
        Directory::open(&parent)?.create_private_directory(OsStr::new(&name))?;
        let directory = TemporaryDirectory(parent.join(name));
        let limits = Limits::default();
        let (files, _) = Files::open(&directory.0, limits, AbsoluteTime::UNIX_EPOCH)?;
        if Files::open(&directory.0, limits, AbsoluteTime::UNIX_EPOCH).is_ok() {
            return Err(
                io::Error::other("second NAMECACHE writer acquired the same directory").into(),
            );
        }

        let query = Block::decode(BLOCK)?.query()?;
        files.commit(&Mutation::Upsert {
            query,
            block: BLOCK.to_vec(),
        })?;
        let replacement_expiry = Block::decode(BLOCK)?.expiration()? + 1;
        let mut replacement = BLOCK.to_vec();
        replacement[104..112].copy_from_slice(&replacement_expiry.to_be_bytes());
        files.commit(&Mutation::Upsert {
            query,
            block: replacement.clone(),
        })?;

        let mut expired = ED_BLOCK.to_vec();
        expired[104..112].copy_from_slice(&1_u64.to_be_bytes());
        let expired_query = Block::decode(&expired)?.query()?;
        files.commit(&Mutation::Upsert {
            query: expired_query,
            block: expired,
        })?;
        let stage = OsStr::new(".gnunet-file-1-2.new");
        files.directory.create_private_file(stage)?;
        drop(files);

        let (files, cache) = Files::open(&directory.0, limits, AbsoluteTime::from_micros(2))?;
        if cache.lookup(&query)?.map(|block| block.as_bytes()) != Some(replacement.as_slice()) {
            return Err(io::Error::other("replacement ciphertext did not survive restart").into());
        }
        if cache.lookup(&expired_query)?.is_some() {
            return Err(io::Error::other("expired record was reloaded").into());
        }
        let names = files.directory.entries()?.collect::<io::Result<Vec<_>>>()?;
        if names.len() != 2 {
            return Err(io::Error::other("unexpected files remained after cache recovery").into());
        }
        files.commit(&Mutation::Delete(query))?;
        drop(files);

        let (_files, cache) = Files::open(&directory.0, limits, AbsoluteTime::from_micros(2))?;
        if cache.stats().entries != 0 {
            return Err(io::Error::other("deleted cache records returned after restart").into());
        }
        Ok(())
    }
}
