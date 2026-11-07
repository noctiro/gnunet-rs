//! Concrete profile dispatch. Only real Quinn-owned Raw/H3 Links construct it.
use crate::{
    raw,
    types::{Buffers, Fault, Limits},
};
use gnunet_transport_quic::{Instance, Role};
use gnunet_types::{Error as Protocol, MonoInstant};
use std::{marker::PhantomData, task::Context};
use tokio::time::Instant;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FrameId<'id> {
    Raw(raw::FrameId<'id>),
    #[cfg(feature = "h3-profile")]
    Http3(crate::h3_link::FrameId<'id>),
}
pub(crate) struct Frame<'a, 'id> {
    pub(crate) id: FrameId<'id>,
    pub(crate) bytes: &'a [u8],
}
#[cfg_attr(
    feature = "h3-profile",
    expect(
        clippy::large_enum_variant,
        reason = "The bounded connection rows own profile state inline without an extra allocation per connection"
    )
)]
pub(crate) enum Application<'id, 'slots, 'buf> {
    Raw(raw::Link<'id, 'buf>, PhantomData<&'slots mut ()>),
    #[cfg(feature = "h3-profile")]
    Http3(crate::h3_link::Link<'id, 'slots, 'buf>),
}
pub(crate) struct Options {
    pub(crate) local: [u8; 32],
    pub(crate) role: Role,
    pub(crate) until: MonoInstant,
    pub(crate) hard: Instant,
    pub(crate) limits: Limits,
}
impl<'id, 'slots, 'buf> Application<'id, 'slots, 'buf> {
    pub(crate) fn adopt(
        connection: &quinn::Connection,
        instance: &'id Instance,
        now: MonoInstant,
        pool: &mut Buffers<'_, 'id, 'slots, 'buf>,
        index: usize,
        options: Options,
    ) -> Result<Self, Fault> {
        let Options {
            local,
            role,
            until,
            hard,
            limits,
        } = options;
        match pool {
            Buffers::Raw(loans) => Ok(Self::Raw(
                raw::Link::adopt(
                    connection,
                    instance,
                    now,
                    loans.get_mut(index).ok_or(Protocol::Capacity)?,
                    gnunet_transport_quic::raw::Options {
                        local,
                        role,
                        until,
                        max_frame: limits.raw_body,
                    },
                )?,
                PhantomData,
            )),
            Buffers::Http3(loans) => {
                #[cfg(feature = "h3-profile")]
                {
                    Ok(Self::Http3(
                        crate::h3_link::Link::adopt(
                            connection,
                            instance,
                            now,
                            loans.get_mut(index).ok_or(Protocol::Capacity)?,
                            crate::h3_link::Options {
                                local,
                                profile: gnunet_transport_quic::h3::Options {
                                    role,
                                    until,
                                    limits: gnunet_transport_quic::h3::Limits {
                                        max_body: limits.h3_body,
                                        header_bytes: limits.h3_headers,
                                        polls: limits.h3_polls,
                                    },
                                },
                                hard,
                                request_timeout: limits.h3_request_timeout,
                                max_requests: limits.h3_requests,
                            },
                        )
                        .map_err(Fault::Http3)?,
                    ))
                }
                #[cfg(not(feature = "h3-profile"))]
                {
                    let _unused = (loans, hard);
                    Err(Protocol::Unsupported.into())
                }
            }
        }
    }
    pub(crate) fn may_send(&self, now: MonoInstant) -> Result<bool, Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.may_send(now)?),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.may_send(now).map_err(Fault::Http3),
        }
    }
    /// Readiness and a free bounded send reservation are separate facts.
    pub(crate) fn send_capacity(&self, now: MonoInstant) -> Result<bool, Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.may_send(now)? && l.pending_send().is_none()),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.send_capacity(now).map_err(Fault::Http3),
        }
    }
    pub(crate) fn frame(&self, now: MonoInstant) -> Result<Option<Frame<'_, 'id>>, Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.frame(now)?.map(|f| Frame {
                id: FrameId::Raw(f.id),
                bytes: f.bytes,
            })),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l
                .frame(now)
                .map(|f| {
                    f.map(|f| Frame {
                        id: FrameId::Http3(f.id),
                        bytes: f.bytes,
                    })
                })
                .map_err(Fault::Http3),
        }
    }
    pub(crate) fn release_frame(&mut self, id: FrameId<'id>) -> Result<usize, Fault> {
        match (self, id) {
            (Self::Raw(l, _), FrameId::Raw(id)) => Ok(l.release_frame(id)?),
            #[cfg(feature = "h3-profile")]
            (Self::Http3(l), FrameId::Http3(id)) => l.release_frame(id).map_err(Fault::Http3),
            #[cfg(feature = "h3-profile")]
            _ => Err(Protocol::Stale.into()),
        }
    }
    pub(crate) fn queue(
        &mut self,
        id: raw::SendId,
        bytes: &[u8],
        hard: Instant,
        now: MonoInstant,
    ) -> Result<(), Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.queue(id, bytes, hard, now)?),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.queue(id, bytes, hard, now).map_err(Fault::Http3),
        }
    }
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
    ) -> Result<raw::Step, Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.poll(cx, now)?),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.poll(cx, now).map_err(Fault::Http3),
        }
    }
    pub(crate) fn take_accepted(&mut self, id: raw::SendId) -> Result<(), Fault> {
        match self {
            Self::Raw(l, _) => Ok(l.take_accepted(id)?),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.take_accepted(id).map_err(Fault::Http3),
        }
    }
    pub(crate) fn pending_send(&self) -> Option<(raw::SendId, usize, usize)> {
        match self {
            Self::Raw(l, _) => l.pending_send(),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.pending_send(),
        }
    }
    pub(crate) fn pending_send_unknown(&self) -> Option<raw::SendId> {
        match self {
            Self::Raw(_, _) => None,
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.pending_send_unknown(),
        }
    }
    pub(crate) fn close(&mut self) {
        match self {
            Self::Raw(l, _) => l.close(),
            #[cfg(feature = "h3-profile")]
            Self::Http3(l) => l.close(),
        }
    }
    pub(crate) fn recycle(
        self,
        pool: &mut Buffers<'_, 'id, 'slots, 'buf>,
        index: usize,
    ) -> Result<(), Fault> {
        match (self, pool) {
            (Self::Raw(l, _), Buffers::Raw(loans)) => {
                *loans.get_mut(index).ok_or(Protocol::Capacity)? = Some(l.recycle()?);
                Ok(())
            }
            #[cfg(feature = "h3-profile")]
            (Self::Http3(l), Buffers::Http3(loans)) => {
                *loans.get_mut(index).ok_or(Protocol::Capacity)? =
                    Some(l.recycle().map_err(Fault::Http3)?);
                Ok(())
            }
            _ => Err(Protocol::Conflict.into()),
        }
    }
}
