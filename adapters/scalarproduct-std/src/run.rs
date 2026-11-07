//! Explicit local futures keep borrowed SDK brands on their own pinned stack.
use crate::{Error, SessionReport, Sources};
use gnunet_cadet_host as cadet;
use gnunet_crypto::Entropy;
use gnunet_service_runtime::framing::Framed;
use gnunet_seti_client_host as seti;
use gnunet_types::Error as Fault;
use std::{
    cell::{Cell, RefCell},
    future::poll_fn,
    rc::Rc,
};
use zeroize::Zeroize;
mod state;

pub(crate) struct Control {
    reason: Cell<Option<Fault>>,
}
impl Control {
    pub fn new() -> Self {
        Self {
            reason: Cell::new(None),
        }
    }
    pub fn cancel(&self, cause: Fault) {
        if self.reason.get().is_none() {
            self.reason.set(Some(cause));
        }
    }
    pub fn reason(&self) -> Option<Fault> {
        self.reason.get()
    }
}
struct Key {
    owner: u64,
    session: [u8; 64],
}
pub(crate) struct Registry {
    keys: Vec<Key>,
}
impl Registry {
    pub fn new(count: usize) -> Result<Self, Fault> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
        Ok(Self { keys })
    }
    pub fn retained_bytes(&self) -> Result<usize, Fault> {
        self.keys
            .capacity()
            .checked_mul(std::mem::size_of::<Key>())
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<RefCell<Self>>() + 2 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or(Fault::Overflow)
    }
}
pub(crate) struct KeyLease {
    registry: Rc<RefCell<Registry>>,
    owner: u64,
}
impl KeyLease {
    pub fn claim(
        registry: Rc<RefCell<Registry>>,
        owner: u64,
        session: [u8; 64],
    ) -> Result<Self, Error> {
        {
            let mut table = registry.try_borrow_mut().map_err(|_| Fault::Conflict)?;
            if table.keys.iter().any(|key| key.session == session) {
                return Err(Fault::Conflict.into());
            }
            if table.keys.len() == table.keys.capacity() {
                return Err(Fault::Capacity.into());
            }
            table.keys.push(Key { owner, session });
        }
        Ok(Self { registry, owner })
    }
}
impl Drop for KeyLease {
    fn drop(&mut self) {
        if let Ok(mut table) = self.registry.try_borrow_mut()
            && let Some(index) = table.keys.iter().position(|key| key.owner == self.owner)
        {
            table.keys.swap_remove(index);
        }
    }
}
pub(crate) struct NativeEntropy {
    error: Option<getrandom::Error>,
}
impl NativeEntropy {
    pub fn new() -> Self {
        Self { error: None }
    }
    pub fn take_error(&mut self) -> Option<getrandom::Error> {
        self.error.take()
    }
}
impl Entropy for NativeEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Fault> {
        match getrandom::fill(output) {
            Ok(()) => Ok(()),
            Err(error) => {
                output.zeroize();
                if self.error.is_none() {
                    self.error = Some(error);
                }
                Err(Fault::EntropyUnavailable)
            }
        }
    }
}

/// Original selected session resources, moved into exactly one local future.
pub(crate) struct Session {
    pub admission: crate::input::Admission,
    pub key: Option<Rc<gnunet_paillier::KeyPair>>,
    pub registry: Rc<RefCell<Registry>>,
    pub control: Rc<Control>,
}
pub(crate) async fn session(
    original: Session,
    mut io: Framed<u64>,
    sources: Sources,
) -> SessionReport {
    let Session {
        admission,
        key,
        registry,
        control,
    } = original;
    let role = admission.role;
    let profile = admission.profile;
    let limits = admission.limits;
    if let Some(cause) = control.reason() {
        io.retire();
        return SessionReport {
            primary: Some(cause.into()),
            physical_closed: true,
            ..SessionReport::default()
        };
    }
    let prepared =
        match crate::input::read(admission, &mut io, sources.clock(), registry, &control).await {
            Ok(prepared) => prepared,
            Err(error) => {
                io.retire();
                return SessionReport {
                    primary: Some(error),
                    physical_closed: true,
                    ..SessionReport::default()
                };
            }
        };
    // Keep this guard until every actual native owner and core debt is retired.
    let _key_lease = prepared.lease;
    if let Some(cause) = control.reason() {
        io.retire();
        return SessionReport {
            role: Some(role),
            primary: Some(cause.into()),
            physical_closed: true,
            ..SessionReport::default()
        };
    }
    let admission = (|| -> Result<(), Error> {
        if tokio::time::Instant::now() >= prepared.native_until {
            return Err(Fault::Deadline.into());
        }
        if sources.clock().sample()?.now.as_micros() >= prepared.canonical_until {
            return Err(Fault::Deadline.into());
        }
        if let Some(cause) = control.reason() {
            return Err(cause.into());
        }
        if tokio::time::Instant::now() >= prepared.native_until {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    })();
    if let Err(error) = admission {
        io.retire();
        return SessionReport {
            role: Some(role),
            primary: Some(error),
            physical_closed: true,
            ..SessionReport::default()
        };
    }
    let brand = crate::backend::Instance::new();
    let mut cadet_brand = cadet::Instance::new();
    let mut set_brand = seti::Instance::new();
    let mut listener_brand = seti::Instance::new();
    let mut ports = [cadet::PortSlot::new(); 1];
    let mut channels = [cadet::ChannelSlot::new(); 2];
    let mut entropy = NativeEntropy::new();
    let core = crate::backend::Computation::new(
        &brand,
        profile,
        role,
        prepared.session,
        prepared.peer,
        prepared.values,
        limits,
        key,
        prepared.canonical_origin,
        &mut entropy,
    );
    let core = match core {
        Ok(core) => core,
        Err(error) => {
            io.retire();
            return SessionReport {
                role: Some(role),
                primary: Some(entropy.take_error().map_or_else(|| error, Error::Entropy)),
                physical_closed: true,
                ..SessionReport::default()
            };
        }
    };
    let listener_source = match sources.seti.duplicate() {
        Ok(source) => source,
        Err(error) => {
            io.retire();
            return SessionReport {
                role: Some(role),
                primary: Some(error.into()),
                physical_closed: true,
                ..SessionReport::default()
            };
        }
    };
    let cadet = match cadet::Client::new(
        &mut cadet_brand,
        sources.cadet,
        &mut ports,
        &mut channels,
        limits.cadet,
    ) {
        Ok(cadet) => cadet,
        Err(error) => {
            io.retire();
            return SessionReport {
                role: Some(role),
                primary: Some(error.into()),
                physical_closed: true,
                ..SessionReport::default()
            };
        }
    };
    let mut state = match state::State::new(
        core,
        cadet,
        io,
        sources.seti,
        listener_source,
        &mut set_brand,
        &mut listener_brand,
        entropy,
        limits,
        prepared.canonical_until,
        prepared.native_until,
        control,
        role,
    ) {
        Ok(state) => state,
        Err(error) => {
            return SessionReport {
                role: Some(role),
                primary: Some(error),
                physical_closed: true,
                ..SessionReport::default()
            };
        }
    };
    poll_fn(|cx| state.poll(cx)).await
}
