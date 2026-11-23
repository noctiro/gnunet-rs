//! Fixed caller-owned receive bodies. TX MTUs never size incoming bodies.
use crate::{Buffers, Fault, Instance, Limits, Runtime, Sources, credentials::Tls, tls::Profile};
use gnunet_types::Error;
use std::{io, net::SocketAddr};
use zeroize::Zeroizing;
type Body = Zeroizing<Vec<u8>>;

pub(crate) struct FramePool {
    profile: Profile,
    limits: Limits,
    budget: usize,
    bodies: Vec<Body>,
    retained_bytes: usize,
}

impl FramePool {
    pub(crate) fn new(profile: Profile, limits: Limits, budget: usize) -> Result<Self, Fault> {
        limits.validate()?;
        let (per_connection, body_len) = match profile {
            Profile::Raw => (1, limits.raw_body),
            Profile::Http3 if cfg!(feature = "h3-profile") => (limits.h3_polls + 2, limits.h3_body),
            Profile::Http3 => return Err(Error::Unsupported.into()),
        };
        let connections = limits.backend.connections;
        let count = connections
            .checked_mul(per_connection)
            .ok_or(Error::Overflow)?;
        let payload = count.checked_mul(body_len).ok_or(Error::Overflow)?;
        let body_metadata = count
            .checked_mul(size_of::<Body>())
            .ok_or(Error::Overflow)?;
        let estimated = payload.checked_add(body_metadata).ok_or(Error::Overflow)?;
        let slots = if profile == Profile::Http3 { count } else { 0 };
        validate_budget(budget, estimated, slots, connections)?;

        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..count {
            let mut body = Zeroizing::new(Vec::new());
            body.try_reserve_exact(body_len)
                .map_err(|_| Error::Capacity)?;
            body.resize(body_len, 0);
            bodies.push(body);
        }
        let body_metadata = bodies
            .capacity()
            .checked_mul(size_of::<Body>())
            .ok_or(Error::Overflow)?;
        let retained_bytes = bodies.iter().try_fold(body_metadata, |total, body| {
            total.checked_add(body.capacity()).ok_or(Error::Overflow)
        })?;
        validate_budget(budget, retained_bytes, slots, connections)?;
        Ok(Self {
            profile,
            limits,
            budget,
            bodies,
            retained_bytes,
        })
    }

    /// The same original loans stay alive through the caller's shutdown.
    pub(crate) async fn run<T, E: From<Fault>>(
        mut self,
        sources: Sources,
        bind: SocketAddr,
        tls: Tls,
        socket_policy: gnunet_service_runtime::network::SocketPolicy,
        drive: impl AsyncFnOnce(&mut Runtime<'_, '_, '_, '_, '_>) -> Result<T, E>,
    ) -> Result<T, E> {
        if tls.profile() != self.profile {
            return Err(Fault::from(Error::Conflict).into());
        }
        let instance = Instance::new();
        let mut pils = gnunet_pils::client::Instance::new();
        match self.profile {
            Profile::Raw => {
                let mut loans = Vec::new();
                loans
                    .try_reserve_exact(self.bodies.len())
                    .map_err(|_| Fault::from(Error::Capacity))?;
                loans.extend(self.bodies.iter_mut().map(|body| Some(body.as_mut_slice())));
                validate_budget(self.budget, self.retained_bytes, 0, loans.capacity())?;
                let mut runtime = Runtime::with_endpoint(
                    &instance,
                    &mut pils,
                    sources,
                    crate::runtime::EndpointSetup {
                        bind,
                        tls,
                        socket_policy,
                    },
                    Buffers::Raw(&mut loans),
                    self.limits,
                )?;
                drive(&mut runtime).await
            }
            #[cfg(feature = "h3-profile")]
            Profile::Http3 => {
                let mut slots = Vec::new();
                slots
                    .try_reserve_exact(self.bodies.len())
                    .map_err(|_| Fault::from(Error::Capacity))?;
                slots.extend(
                    self.bodies
                        .iter_mut()
                        .map(|body| gnunet_transport_quic::h3::Slot::new(body.as_mut_slice())),
                );
                let slot_capacity = slots.capacity();
                let mut loans = Vec::new();
                loans
                    .try_reserve_exact(self.limits.backend.connections)
                    .map_err(|_| Fault::from(Error::Capacity))?;
                loans.extend(slots.chunks_mut(self.limits.h3_polls + 2).map(Some));
                validate_budget(
                    self.budget,
                    self.retained_bytes,
                    slot_capacity,
                    loans.capacity(),
                )?;
                let mut runtime = Runtime::with_endpoint(
                    &instance,
                    &mut pils,
                    sources,
                    crate::runtime::EndpointSetup {
                        bind,
                        tls,
                        socket_policy,
                    },
                    Buffers::Http3(&mut loans),
                    self.limits,
                )?;
                drive(&mut runtime).await
            }
            #[cfg(not(feature = "h3-profile"))]
            Profile::Http3 => Err(Fault::from(Error::Unsupported).into()),
        }
    }
}

fn validate_budget(
    budget: usize,
    body_bytes: usize,
    slots: usize,
    handles: usize,
) -> Result<(), Fault> {
    // Both loan kinds hold a fat mutable slice. Charge actual retained vector
    // capacities, including H3 slot metadata separately from its body slabs.
    let slot_bytes = slots
        .checked_mul(size_of::<gnunet_transport_quic::h3::Slot<'_, '_>>())
        .ok_or(Error::Overflow)?;
    let handle_bytes = handles
        .checked_mul(size_of::<Option<&mut [u8]>>())
        .ok_or(Error::Overflow)?;
    let total = body_bytes
        .checked_add(slot_bytes)
        .and_then(|bytes| bytes.checked_add(handle_bytes))
        .ok_or(Error::Overflow)?;
    if total > budget {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "QUIC receive pool exceeds FRAME_POOL_BYTES",
        )
        .into());
    }
    Ok(())
}
