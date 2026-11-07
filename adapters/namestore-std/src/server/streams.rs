//! Private multiplexing of actual original pure stream outputs.
use gnunet_namestore::{
    Core, Item, Monitor, Prepared, StreamLimits, StreamLoss, StreamProgress, Write, ZoneIterator,
};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Response;
pub(super) enum Driver {
    Iterator {
        request: u32,
        generation: u64,
        owner: ZoneIterator,
    },
    Monitor {
        generation: u64,
        opened: u64,
        offered: u64,
        owner: Monitor,
    },
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Target {
    Iterator { request: u32, generation: u64 },
    Monitor { generation: u64 },
}
impl Driver {
    pub fn target(&self) -> Target {
        match self {
            Self::Iterator {
                request,
                generation,
                ..
            } => Target::Iterator {
                request: *request,
                generation: *generation,
            },
            Self::Monitor { generation, .. } => Target::Monitor {
                generation: *generation,
            },
        }
    }
    pub fn request(&self) -> Option<u32> {
        match self {
            Self::Iterator { request, .. } => Some(*request),
            Self::Monitor { .. } => None,
        }
    }
    pub fn prepare(&mut self, core: &Core, now: u64) -> Result<StreamProgress, Error> {
        match self {
            Self::Iterator { owner, .. } => owner.prepare(core, now),
            Self::Monitor { owner, .. } => owner.prepare(core, now),
        }
    }
    pub fn prepared(&self) -> Option<Prepared<'_>> {
        match self {
            Self::Iterator { owner, .. } => owner.prepared(),
            Self::Monitor { owner, .. } => owner.prepared(),
        }
    }
    pub fn grant(&mut self, n: u64) -> Result<(), Error> {
        match self {
            Self::Iterator { owner, .. } => owner.grant(n),
            Self::Monitor { owner, .. } => owner.grant(n),
        }
    }
    pub fn can_queue(&self, w: &Write) -> Result<(), Error> {
        match self {
            Self::Iterator { owner, .. } => owner.can_queue(w),
            Self::Monitor { owner, .. } => owner.can_queue(w),
        }
    }
    pub fn queued(&mut self, w: &Write) -> Result<(), Error> {
        match self {
            Self::Iterator { owner, .. } => owner.queued(w),
            Self::Monitor { owner, .. } => owner.queued(w),
        }
    }
    pub fn exposed(&mut self, w: &Write) -> Result<(), Error> {
        match self {
            Self::Iterator { owner, .. } => owner.exposed(w),
            Self::Monitor { owner, .. } => owner.exposed(w),
        }
    }
    pub fn written(&mut self, w: &Write) -> Result<(), Error> {
        match self {
            Self::Iterator { owner, .. } => owner.written(w),
            Self::Monitor { owner, .. } => owner.written(w),
        }
    }
    pub fn stop(&mut self) {
        match self {
            Self::Iterator { owner, .. } => owner.stop(),
            Self::Monitor { owner, .. } => owner.stop(),
        }
    }
    pub fn lost(&mut self) -> StreamLoss {
        match self {
            Self::Iterator { owner, .. } => owner.source_lost(),
            Self::Monitor { owner, .. } => owner.source_lost(),
        }
    }
}
pub(super) fn response<'a>(item: Item<'a>) -> Result<Response<'a>, Error> {
    match item {
        Item::Record { request, query } => Ok(Response::Records {
            rid: request,
            zone: query.zone().view()?,
            label: gnunet_wire::official::namestore::CString::new(query.label())?,
            expires: gnunet_wire::official::AbsoluteTime::from_micros(query.expires()),
            records: query.records()?,
        }),
        Item::End { request } => Ok(Response::End { rid: request }),
        Item::Sync => Ok(Response::MonitorSync),
    }
}
// The aliases remain explicit in the enclosing server's constructor contract.
pub(super) fn validate_limits(limits: StreamLimits) -> Result<(), Error> {
    if limits.changes == 0
        || limits.changes > 4096
        || limits.scan_rows == 0
        || limits.scan_rows > 65535
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
