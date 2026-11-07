use gnunet_types::Error;
/// Read-only cause of an original operation's retained final FAILURE response.
/// Numeric generations identify local diagnostics only; they grant no owner or
/// delivery authority and do not change the official result status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationFailure {
    /// Original immutable final response's local effect generation.
    pub effect_serial: u64,
    /// Original local client/source generation.
    pub client_serial: u64,
    /// Original local operation generation, independent of the wire request ID.
    pub operation_serial: u64,
    /// Original official request ID on that client source.
    pub request_id: u32,
    /// Original set operation.
    pub kind: OperationType,
    /// First actual failure retained by the original protocol engine.
    pub reason: Error,
    /// Original canonical operation deadline; diagnostic, never a new budget.
    pub expires: u64,
}
/// Public operation supported by one original generic SET handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OperationType {
    /// Public purely local set; it cannot be evaluated against a peer.
    Local = 0,
    /// Intersection of original frozen memberships.
    Intersection = 1,
    /// Union of original frozen memberships.
    Union = 2,
}
impl TryFrom<u32> for OperationType {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Local),
            1 => Ok(Self::Intersection),
            2 => Ok(Self::Union),
            _ => Err(Error::InvalidInput),
        }
    }
}
/// Public client result mode; it does not change any original set membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResultMode {
    /// All resulting intersection elements.
    Full = 0,
    /// Union ADD_LOCAL/ADD_REMOTE notifications with their public meaning.
    Symmetric = 1,
    /// Elements removed by an intersection.
    Removed = 2,
    /// Elements added by a union.
    Added = 3,
}
impl TryFrom<u32> for ResultMode {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::Symmetric),
            2 => Ok(Self::Removed),
            3 => Ok(Self::Added),
            _ => Err(Error::InvalidInput),
        }
    }
}
impl ResultMode {
    /// Validate the public mode/operation contract before admitting an intent.
    pub fn validate(self, operation: OperationType) -> Result<(), Error> {
        if matches!(
            (operation, self),
            (OperationType::Intersection, Self::Full | Self::Removed)
                | (OperationType::Union, Self::Symmetric | Self::Added)
        ) {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}
/// Actual public result status. HALF_DONE is explicitly not operation completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    /// Actual result element for FULL/ADDED/REMOVED.
    Ok = 0,
    /// Union element missing locally.
    AddLocal = 1,
    /// Union element proven missing remotely.
    AddRemote = 2,
    /// Original operation refused or failed.
    Failure = 3,
    /// Local union receive results are complete; original sends may remain.
    HalfDone = 4,
    /// Original send and receive protocol has genuinely finished.
    Done = 5,
}
impl TryFrom<u16> for Status {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::AddLocal),
            2 => Ok(Self::AddRemote),
            3 => Ok(Self::Failure),
            4 => Ok(Self::HalfDone),
            5 => Ok(Self::Done),
            _ => Err(Error::Malformed),
        }
    }
}
impl Status {
    /// Public operation terminal, without treating HALF_DONE as success.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failure)
    }
}
