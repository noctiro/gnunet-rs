//! Official gnunet-datastore binary backup, not FS repository import/export.
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, MAX_VALUE_BYTES},
};
pub(super) const MAGIC: [u8; 16] = *b"GNUNETDATASTORE1";
pub(super) const HEADER: usize = 92;
#[derive(Clone, Copy)]
pub(super) struct Record {
    pub size: usize,
    pub kind: u32,
    pub priority: u32,
    pub anonymity: u32,
    pub replication: u32,
    pub expiration: AbsoluteTime,
    pub key: [u8; 64],
}
fn word(bytes: &[u8; HEADER], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
impl Record {
    pub fn decode(bytes: &[u8; HEADER]) -> Result<Self, Error> {
        let size = usize::try_from(word(bytes, 0)?).map_err(|_| Error::TooLarge)?;
        if size > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut key = [0; 64];
        key.copy_from_slice(&bytes[28..92]);
        Ok(Self {
            size,
            kind: word(bytes, 4)?,
            priority: word(bytes, 8)?,
            anonymity: word(bytes, 12)?,
            replication: word(bytes, 16)?,
            expiration: AbsoluteTime::from_micros(u64::from_be_bytes(
                bytes[20..28].try_into().map_err(|_| Error::Truncated)?,
            )),
            key,
        })
    }
    pub fn from_data(data: Data<'_>) -> Result<Self, Error> {
        if data.value.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            size: data.value.len(),
            kind: data.kind,
            priority: data.priority,
            anonymity: data.anonymity,
            replication: data.replication,
            expiration: data.expiration,
            key: *data.key,
        })
    }
    pub fn encode(self) -> Result<[u8; HEADER], Error> {
        if self.size > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut out = [0; HEADER];
        for (offset, value) in [
            (0, u32::try_from(self.size).map_err(|_| Error::TooLarge)?),
            (4, self.kind),
            (8, self.priority),
            (12, self.anonymity),
            (16, self.replication),
        ] {
            out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        out[20..28].copy_from_slice(&self.expiration.as_micros().to_be_bytes());
        out[28..92].copy_from_slice(&self.key);
        Ok(out)
    }
    pub fn put<'a>(&'a self, value: &'a [u8]) -> Result<Data<'a>, Error> {
        if self.size != value.len() {
            return Err(Error::InvalidInput);
        }
        Ok(Data {
            reservation: 0,
            kind: self.kind,
            priority: self.priority,
            anonymity: self.anonymity,
            replication: self.replication,
            uid: 0,
            expiration: self.expiration,
            key: &self.key,
            value,
        })
    }
}
