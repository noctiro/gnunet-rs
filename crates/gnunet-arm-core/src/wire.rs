//! ARM v0.29.1 ABI-framed messages with explicit C aggregate alignment profile.
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, MessageType, message_type as mt};
/// Official public ARM API version, independent from IPC framing.
pub const VERSION: u32 = 3;
/// Packed command prefix size, including common framing.
pub const COMMAND_BYTES: usize = 16;
/// Official C aggregate-layout profile, selected explicitly by the peer's ABI.
/// This is not inferred from Rust pointer width and is not encoded on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmAbi {
    /// C uint64_t alignment8: RESULT24, LIST_RESULT prefix24.
    U64Align8,
    /// C uint64_t alignment4: RESULT20, LIST_RESULT prefix20.
    /// This profile requires separate normal-platform interoperability evidence.
    U64Align4,
}
impl ArmAbi {
    /// Complete fixed result sizeof from the selected C aggregate ABI.
    pub const fn result_bytes(self) -> usize {
        match self {
            Self::U64Align8 => 24,
            Self::U64Align4 => 20,
        }
    }
    /// List prefix sizeof, including trailing native alignment bytes.
    pub const fn list_bytes(self) -> usize {
        match self {
            Self::U64Align8 => 24,
            Self::U64Align4 => 20,
        }
    }
}
/// One C service-info entry width; its absolute-time members are packed.
pub const INFO_BYTES: usize = 28;
/// Opaque monotonically assigned request identity encoded BE64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireId(pub u64);
/// Public result code; future/unknown numeric values remain lossless.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultCode(pub u32);
impl ResultCode {
    /// Service stopped (ARM itself is synthesized only after connection loss).
    pub const STOPPED: Self = Self(0);
    /// ARM shutdown initiated.
    pub const STOPPING: Self = Self(1);
    /// Service start initiated, not proof that it reached readiness.
    pub const STARTING: Self = Self(2);
    /// Already starting.
    pub const IS_STARTING_ALREADY: Self = Self(3);
    /// Already stopping.
    pub const IS_STOPPING_ALREADY: Self = Self(4);
    /// Already running.
    pub const IS_STARTED_ALREADY: Self = Self(5);
    /// Already stopped.
    pub const IS_STOPPED_ALREADY: Self = Self(6);
    /// Unknown configured service.
    pub const IS_NOT_KNOWN: Self = Self(7);
    /// Process creation/command setup failed.
    pub const START_FAILED: Self = Self(8);
    /// Cannot start during ARM shutdown.
    pub const IN_SHUTDOWN: Self = Self(9);
}
/// Monitor notification code, including unknown numeric values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorStatus(pub u32);
impl MonitorStatus {
    /// Registration dummy, sent for service arm only, without a snapshot.
    pub const MONITORING_STARTED: Self = Self(0);
    /// Service exited.
    pub const STOPPED: Self = Self(1);
    /// Start initiated.
    pub const STARTING: Self = Self(2);
    /// Stop initiated.
    pub const STOPPING: Self = Self(3);
}
/// Service-list state, distinct from monitor statuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceStatus(pub u32);
impl ServiceStatus {
    /// Never started.
    pub const STOPPED: Self = Self(0);
    /// Process present and not waiting for stop.
    pub const STARTED: Self = Self(1);
    /// Nonzero prior process exit.
    pub const FAILED: Self = Self(2);
    /// Prior normal exit0.
    pub const FINISHED: Self = Self(3);
    /// Process present with pending stop or global shutdown.
    pub const STOPPING: Self = Self(4);
}
/// ARM client callback request status; disconnected has no defined result/list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RequestStatus {
    /// Received a result or local start notification.
    SentOk = 0,
    /// Owner disconnected before a terminal response.
    Disconnected = 2,
}
fn prefix(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
fn terminated(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.last() != Some(&0) {
        return Err(Error::Malformed);
    }
    Ok(prefix(bytes))
}
fn u16_at(bytes: &[u8], n: usize) -> Result<u16, Error> {
    let a: [u8; 2] = bytes
        .get(n..n + 2)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u16::from_be_bytes(a))
}
fn u32_at(bytes: &[u8], n: usize) -> Result<u32, Error> {
    let a: [u8; 4] = bytes
        .get(n..n + 4)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_be_bytes(a))
}
fn u64_at(bytes: &[u8], n: usize) -> Result<u64, Error> {
    let a: [u8; 8] = bytes
        .get(n..n + 8)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_be_bytes(a))
}
fn preflight(kind: MessageType, size: usize, out: &[u8]) -> Result<MessageHeader, Error> {
    let header = MessageHeader::from_total_size(kind, size)?;
    if out.len() < size {
        return Err(Error::Capacity);
    }
    Ok(header)
}
/// Borrowed canonical request. Service names follow C strlen/interior-NUL rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Start named service; stdio inheritance is local-only for starting ARM.
    Start {
        /// Alignment field, ignored by the daemon.
        reserved: u32,
        /// Original wire identity.
        id: WireId,
        /// Effective C-string service name before terminating NUL.
        service: &'a [u8],
    },
    /// Stop named service; stopping ARM waits for its IPC disconnect.
    Stop {
        /// Ignored alignment field.
        reserved: u32,
        /// Original wire identity.
        id: WireId,
        /// Effective C-string service name.
        service: &'a [u8],
    },
    /// List all configured services, including stopped entries.
    List {
        /// Nonzero triggers only a C diagnostic, not rejection.
        reserved: u32,
        /// Original wire identity.
        id: WireId,
    },
    /// Subscribe to status changes on a separate monitor handle.
    Monitor,
    /// Prove the ARM MQ peer responds; this is the actual initial handshake.
    Test,
}
impl Request<'_> {
    /// Complete canonical frame length; source permits65535, reject65536.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let size = match self {
            Self::Start { service, .. } | Self::Stop { service, .. } => 16usize
                .checked_add(prefix(service).len())
                .and_then(|n| n.checked_add(1))
                .ok_or(Error::Overflow)?,
            Self::List { .. } => 16,
            Self::Monitor | Self::Test => 4,
        };
        MessageHeader::from_total_size(self.kind(), size)?;
        Ok(size)
    }
    /// Official assignment of this request, without invented private fields.
    pub const fn kind(self) -> MessageType {
        match self {
            Self::Start { .. } => mt::ARM_START,
            Self::Stop { .. } => mt::ARM_STOP,
            Self::List { .. } => mt::ARM_LIST,
            Self::Monitor => mt::ARM_MONITOR,
            Self::Test => mt::ARM_TEST,
        }
    }
    /// Encode after all size checks; rejection leaves every destination byte intact.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        preflight(self.kind(), size, out)?.encode(out)?;
        match self {
            Self::Start {
                reserved,
                id,
                service,
            }
            | Self::Stop {
                reserved,
                id,
                service,
            } => {
                out[4..8].copy_from_slice(&reserved.to_be_bytes());
                out[8..16].copy_from_slice(&id.0.to_be_bytes());
                out[16..size - 1].copy_from_slice(prefix(service));
                out[size - 1] = 0;
            }
            Self::List { reserved, id } => {
                out[4..8].copy_from_slice(&reserved.to_be_bytes());
                out[8..16].copy_from_slice(&id.0.to_be_bytes());
            }
            Self::Monitor | Self::Test => {}
        }
        Ok(size)
    }
}
impl<'a> Request<'a> {
    /// Decode exactly one frame; accepted C-string tails are semantically truncated
    /// at the first NUL, while the final wire byte must also be NUL.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        let t = f.header().message_type();
        if t == mt::ARM_TEST || t == mt::ARM_MONITOR {
            if bytes.len() != 4 {
                return Err(Error::Malformed);
            }
            return Ok(if t == mt::ARM_TEST {
                Self::Test
            } else {
                Self::Monitor
            });
        }
        if t != mt::ARM_START && t != mt::ARM_STOP && t != mt::ARM_LIST {
            return Err(Error::Unsupported);
        }
        let reserved = u32_at(bytes, 4)?;
        let id = WireId(u64_at(bytes, 8)?);
        if t == mt::ARM_LIST {
            if bytes.len() != 16 {
                return Err(Error::Malformed);
            }
            return Ok(Self::List { reserved, id });
        }
        let service = terminated(bytes.get(16..).ok_or(Error::Truncated)?)?;
        Ok(if t == mt::ARM_START {
            Self::Start {
                reserved,
                id,
                service,
            }
        } else {
            Self::Stop {
                reserved,
                id,
                service,
            }
        })
    }
}
/// ABI-sized result, keeping unknown numeric values; tail padding is ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultReply {
    /// Ignored alignment field, not validated as zero by the C client.
    pub reserved: u32,
    /// Echoed request ID.
    pub id: WireId,
    /// Raw result code.
    pub result: ResultCode,
}
impl ResultReply {
    /// Encode atomically at the official fixed width.
    pub fn encode(self, abi: ArmAbi, out: &mut [u8]) -> Result<usize, Error> {
        preflight(mt::ARM_RESULT, abi.result_bytes(), out)?.encode(out)?;
        out[4..8].copy_from_slice(&self.reserved.to_be_bytes());
        out[8..16].copy_from_slice(&self.id.0.to_be_bytes());
        out[16..20].copy_from_slice(&self.result.0.to_be_bytes());
        out[20..abi.result_bytes()].fill(0);
        Ok(abi.result_bytes())
    }
    /// Decode fixed width, rejecting result-tail bytes as MQ does.
    pub fn decode(abi: ArmAbi, bytes: &[u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if f.header().message_type() != mt::ARM_RESULT {
            return Err(Error::Unsupported);
        }
        if bytes.len() != abi.result_bytes() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            reserved: u32_at(bytes, 4)?,
            id: WireId(u64_at(bytes, 8)?),
            result: ResultCode(u32_at(bytes, 16)?),
        })
    }
}
/// Borrowed monitor notification; its unknown status is valid wire data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status<'a> {
    /// Monitor status, not ServiceStatus.
    pub status: MonitorStatus,
    /// Effective C-string name, with no UTF8 requirement.
    pub service: &'a [u8],
}
impl Status<'_> {
    /// Encode name with one NUL, atomically after framing checks.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let name = prefix(self.service);
        let size = 9usize.checked_add(name.len()).ok_or(Error::Overflow)?;
        preflight(mt::ARM_STATUS, size, out)?.encode(out)?;
        out[4..8].copy_from_slice(&self.status.0.to_be_bytes());
        out[8..size - 1].copy_from_slice(name);
        out[size - 1] = 0;
        Ok(size)
    }
}
impl<'a> Status<'a> {
    /// Decode requiring at least one final-NUL string byte.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if f.header().message_type() != mt::ARM_STATUS {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            status: MonitorStatus(u32_at(bytes, 4)?),
            service: terminated(bytes.get(8..).ok_or(Error::Truncated)?)?,
        })
    }
}
/// Borrowed public service-info row, independent from native structure alignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceInfo<'a> {
    /// Exact native C-string service bytes.
    pub name: &'a [u8],
    /// Exact native C-string binary bytes.
    pub binary: &'a [u8],
    /// Public list status, including unknown codes.
    pub status: ServiceStatus,
    /// Source client uses ntohs then promotes to int; FFFF becomes65535, not-1.
    pub last_exit_status: u16,
    /// Raw absolute UTC microseconds, including FOREVER.
    pub restart_at: u64,
    /// Raw absolute UTC microseconds, including zero.
    pub last_started_at: u64,
}
impl ServiceInfo<'_> {
    /// Match actual C public callback integer promotion, not signed i16 reinterpretation.
    pub const fn public_exit_status(self) -> i32 {
        self.last_exit_status as i32
    }
}
fn pool_get(pool: &[u8], index: usize) -> Result<&[u8], Error> {
    let tail = pool
        .get(index..)
        .filter(|b| !b.is_empty())
        .ok_or(Error::Malformed)?;
    let n = tail.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
    Ok(&tail[..n])
}
/// Fully validated borrowed list; all offsets are checked before any callback.
/// Local RX storage cannot be returned as a longer-lived list:
///
/// ```compile_fail,E0515
/// use gnunet_arm_core::wire::{ArmAbi,List};
/// use gnunet_types::Error;
/// fn escape<'a>() -> Result<List<'a>, Error> {
///     let local = [0u8; 18];
///     List::decode(ArmAbi::U64Align8,&local)
/// }
/// ```
///
/// Borrowing the caller's persistent RX instead is valid:
///
/// ```
/// use gnunet_arm_core::wire::{ArmAbi,List};
/// use gnunet_types::Error;
/// fn received<'a>(rx: &'a [u8]) -> Result<List<'a>, Error> { List::decode(ArmAbi::U64Align8,rx) }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct List<'a> {
    bytes: &'a [u8],
    count: u16,
    pool_start: usize,
    prefix: usize,
}
impl<'a> List<'a> {
    /// Decode count×28 and every name/binary pool index. Source permits middle-of-
    /// string indices, duplicate/overlapping strings and unused trailing bytes.
    pub fn decode(abi: ArmAbi, bytes: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if f.header().message_type() != mt::ARM_LIST_RESULT {
            return Err(Error::Unsupported);
        }
        let count = u16_at(bytes, 16)?;
        let prefix = abi.list_bytes();
        let pool_start = prefix + usize::from(count) * 28;
        let pool = bytes.get(pool_start..).ok_or(Error::Malformed)?;
        for i in 0..usize::from(count) {
            let row = &bytes[prefix + i * 28..prefix + (i + 1) * 28];
            pool_get(pool, usize::from(u16_at(row, 0)?))?;
            pool_get(pool, usize::from(u16_at(row, 2)?))?;
        }
        Ok(Self {
            bytes,
            count,
            pool_start,
            prefix,
        })
    }
    /// Number of public service-info entries.
    pub const fn len(self) -> usize {
        self.count as usize
    }
    /// Whether the list has no entries; an unused string pool is still allowed.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }
    /// Original ignored alignment field.
    pub fn reserved(self) -> Result<u32, Error> {
        u32_at(self.bytes, 4)
    }
    /// Original request ID.
    pub fn id(self) -> Result<WireId, Error> {
        Ok(WireId(u64_at(self.bytes, 8)?))
    }
    /// Borrow one fully validated public row; padding remains semantically ignored.
    pub fn get(self, index: usize) -> Result<Option<ServiceInfo<'a>>, Error> {
        if index >= self.len() {
            return Ok(None);
        }
        let row = &self.bytes[self.prefix + index * 28..self.prefix + (index + 1) * 28];
        let pool = &self.bytes[self.pool_start..];
        Ok(Some(ServiceInfo {
            name: pool_get(pool, usize::from(u16_at(row, 0)?))?,
            binary: pool_get(pool, usize::from(u16_at(row, 2)?))?,
            last_exit_status: u16_at(row, 4)?,
            status: ServiceStatus(u32_at(row, 8)?),
            restart_at: u64_at(row, 12)?,
            last_started_at: u64_at(row, 20)?,
        }))
    }
    /// Copy the exact validated wire representation, including reserved/trailing bytes.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.bytes.len() {
            return Err(Error::Capacity);
        }
        out[..self.bytes.len()].copy_from_slice(self.bytes);
        Ok(self.bytes.len())
    }
}
/// Construct canonical server list with zero alignment/padding and sequential
/// name/binary pool. All count, offset and total-size checks precede writes.
pub fn encode_list(
    abi: ArmAbi,
    id: WireId,
    rows: &[ServiceInfo<'_>],
    out: &mut [u8],
) -> Result<usize, Error> {
    let count = u16::try_from(rows.len()).map_err(|_| Error::TooLarge)?;
    let fixed = abi
        .list_bytes()
        .checked_add(rows.len().checked_mul(28).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    let mut size = fixed;
    for row in rows {
        size = size
            .checked_add(prefix(row.name).len())
            .and_then(|n| n.checked_add(prefix(row.binary).len()))
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)?;
    }
    let header = preflight(mt::ARM_LIST_RESULT, size, out)?;
    header.encode(out)?;
    out[4..8].fill(0);
    out[8..16].copy_from_slice(&id.0.to_be_bytes());
    out[16..18].copy_from_slice(&count.to_be_bytes());
    out[18..abi.list_bytes()].fill(0);
    let mut pos = 0usize;
    for (i, row) in rows.iter().enumerate() {
        let offset = abi.list_bytes() + i * 28;
        let name = prefix(row.name);
        let binary = prefix(row.binary);
        out[offset..offset + 2].copy_from_slice(&(pos as u16).to_be_bytes());
        out[fixed + pos..fixed + pos + name.len()].copy_from_slice(name);
        pos += name.len();
        out[fixed + pos] = 0;
        pos += 1;
        out[offset + 2..offset + 4].copy_from_slice(&(pos as u16).to_be_bytes());
        out[fixed + pos..fixed + pos + binary.len()].copy_from_slice(binary);
        pos += binary.len();
        out[fixed + pos] = 0;
        pos += 1;
        out[offset + 4..offset + 6].copy_from_slice(&row.last_exit_status.to_be_bytes());
        out[offset + 6..offset + 8].fill(0);
        out[offset + 8..offset + 12].copy_from_slice(&row.status.0.to_be_bytes());
        out[offset + 12..offset + 20].copy_from_slice(&row.restart_at.to_be_bytes());
        out[offset + 20..offset + 28].copy_from_slice(&row.last_started_at.to_be_bytes());
    }
    Ok(size)
}
