use super::{Bounds, EndpointSource, Failure, Resolver, Shared};
use crate::options::Settings;
use gnunet_identity_client_host as id;
use gnunet_pils::{HelloLimits, client::Inbound};
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::clock::Deadline;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub(super) struct Selectors {
    pub identity: EndpointSource,
    pub pils: EndpointSource,
    pub gns: EndpointSource,
    pub conversation: EndpointSource,
}
impl Selectors {
    pub fn new(
        live: gnunet_client_host::LiveConfiguration,
        resolver: &Resolver,
    ) -> Result<Self, Failure> {
        let source = |name: &'static [u8]| {
            EndpointSource::live(
                live.clone(),
                name,
                resolver.driver.context().resolution_context(),
            )
        };
        let identity = source(b"identity");
        let pils = source(b"pils");
        let gns = source(b"gns");
        let conversation = source(b"conversation");
        let [identity, pils, gns, conversation] =
            EndpointSource::snapshot_all([&identity, &pils, &gns, &conversation])?;
        Ok(Self {
            identity: identity.fixed_endpoint()?,
            pils: pils.fixed_endpoint()?,
            gns: gns.fixed_endpoint()?,
            conversation: conversation.fixed_endpoint()?,
        })
    }
}
/// Original lookup, current ego directory and verified peer identity. None of
/// these sources may replace an established phone's selected ego key. Healthy
/// peer changes update future phone addresses on the same verified PILS MQ;
/// existing SDK calls and their original bytes remain with their own owners.
pub(super) struct Sources<'id, 'p> {
    lookup: Option<id::Lookup<'id>>,
    monitor: id::Client<'id>,
    pils: pils::Client<'p, 1>,
    name: Option<Vec<u8>>,
    public: Option<[u8; 36]>,
    secret: Option<id::SecretKey>,
    ego: Option<id::Ego<'id>>,
    peer: Option<[u8; 32]>,
    peer_epoch: Option<gnunet_pils::client::Epoch<'p>>,
    peer_deadline: Option<Pin<Box<Deadline>>>,
    closed: bool,
    ready: bool,
    turn: usize,
    facts: Shared,
}
pub(super) struct Domains<'id, 'p> {
    pub lookup: &'id id::Instance,
    pub monitor: &'id id::Instance,
    pub pils: &'p mut gnunet_pils::client::Instance,
}
impl<'id, 'p> Sources<'id, 'p> {
    pub fn new(
        domains: Domains<'id, 'p>,
        selectors: &Selectors,
        name: &[u8],
        startup: Bounds,
        settings: &Settings,
        facts: Shared,
    ) -> Result<Self, Failure> {
        let lookup = id::Lookup::exact(
            domains.lookup,
            selectors.identity.duplicate()?,
            name,
            startup.expires,
            settings.identity,
        )?;
        let monitor = id::Client::monitor(
            domains.monitor,
            selectors.identity.duplicate()?,
            settings.identity,
        )?;
        let pils = pils::Client::new(
            domains.pils,
            selectors.pils.duplicate()?,
            settings.pils_profile,
            pils::Limits {
                pending_operations: 1,
                ..Default::default()
            },
            HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 128,
            },
        )?;
        Ok(Self {
            lookup: Some(lookup),
            monitor,
            pils,
            name: None,
            public: None,
            secret: None,
            ego: None,
            peer: None,
            peer_epoch: None,
            peer_deadline: None,
            closed: false,
            ready: false,
            turn: 0,
            facts,
        })
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    pub fn secret(&self) -> Result<&id::SecretKey, Failure> {
        self.secret
            .as_ref()
            .ok_or_else(|| "original IDENTITY ego is unavailable".into())
    }
    pub fn peer(&self) -> Result<[u8; 32], Failure> {
        self.peer
            .ok_or_else(|| "no verified current PILS peer".into())
    }
    fn validate(&mut self) -> Result<(), Failure> {
        if !self.monitor.initialized() || self.public.is_none() {
            return Ok(());
        }
        let original = self.public.ok_or("missing original ego public key")?;
        let name = self
            .name
            .as_ref()
            .ok_or("missing original canonical ego name")?;
        if let Some(ego) = self.ego {
            let view = self.monitor.ego(ego)?;
            if view.public_key()? != original || view.name() != name {
                return Err(
                    "selected actual IDENTITY ego changed while the original phone was active"
                        .into(),
                );
            }
        } else {
            let view = self.monitor.egos().find(|view| view.name() == name);
            let Some(view) = view else {
                return Err(
                    "original lookup ego is absent from actual initial IDENTITY monitor".into(),
                );
            };
            if view.public_key()? != original {
                return Err("original lookup/monitor IDENTITY snapshots differ".into());
            }
            self.ego = Some(view.ego());
        }
        self.ready = self.peer.is_some();
        Ok(())
    }
    fn valid_peer(&self) -> Result<(), Failure> {
        if self.peer.is_some() {
            let identity = self
                .pils
                .identity()
                .ok_or("original PILS identity was revoked")?;
            if Some(identity.epoch()) != self.peer_epoch
                || Some(*identity.peer().as_bytes()) != self.peer
            {
                return Err("original PILS peer/epoch changed".into());
            }
            if identity.expiration() <= self.pils.clock().sample()?.now {
                return Err(
                    "original PILS announcement expired before this phone operation".into(),
                );
            }
        }
        Ok(())
    }
    pub fn check(&self) -> Result<(), Failure> {
        if self.closed {
            return Err("original public sources are physically closed".into());
        }
        self.valid_peer()
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        if self.closed {
            return Poll::Pending;
        }
        self.valid_peer()?;
        if let Some(alarm) = &mut self.peer_deadline {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Err("original PILS identity expired".into()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
        }
        let start = self.turn;
        self.turn = (start + 1) % 3;
        for offset in 0..3 {
            match (start + offset) % 3 {
                0 => {
                    if let Some(lookup) = &mut self.lookup {
                        match lookup.poll(cx, None) {
                            Poll::Pending => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Ready(Ok(event)) => {
                                match event {
                                    id::LookupProgress::Finished { outcome, .. } => {
                                        match outcome {
                                            id::LookupOutcome::Found(identity) => {
                                                self.public = Some(identity.public_key()?);
                                                self.name = Some(crate::options::copy(
                                                    identity.name(),
                                                    1024,
                                                    false,
                                                )?);
                                                self.secret = Some(identity.into_secret());
                                                self.facts.borrow_mut().identity_found = true;
                                            }
                                            id::LookupOutcome::ResultCode(code) => {
                                                self.facts.borrow_mut().identity_result =
                                                    Some(code);
                                                return Poll::Ready(Err(format!("original IDENTITY exact lookup returned service code {code}").into()));
                                            }
                                            id::LookupOutcome::Local {
                                                reason,
                                                submission,
                                                result_code,
                                            } => {
                                                self.facts.borrow_mut().identity_local =
                                                    Some((reason, submission, result_code));
                                                return Poll::Ready(Err("original IDENTITY lookup ended locally without its ego callback; actual exposure retained".into()));
                                            }
                                        }
                                        self.lookup = None;
                                    }
                                    id::LookupProgress::Source(id::Progress::Lost {
                                        report,
                                        cause,
                                    }) => {
                                        {
                                            let mut facts = self.facts.borrow_mut();
                                            facts.identity_lookup_retired = Some((
                                                report.operations,
                                                report.exposed,
                                                report.egos,
                                            ));
                                            facts.identity_cause = Some(cause);
                                        }
                                        return Poll::Ready(Err(
                                            "original exact IDENTITY lookup source was lost".into(),
                                        ));
                                    }
                                    id::LookupProgress::Source(id::Progress::Unavailable(e)) => {
                                        return Poll::Ready(Err(e.into()));
                                    }
                                    id::LookupProgress::Source(id::Progress::ConnectRetry {
                                        error,
                                        ..
                                    }) => self.facts.borrow_mut().retry("IDENTITY lookup", error),
                                    id::LookupProgress::Closed => {
                                        return Poll::Ready(Err(
                                            "IDENTITY lookup closed without an actual result"
                                                .into(),
                                        ));
                                    }
                                    _ => {}
                                }
                                self.validate()?;
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                }
                1 => match self.monitor.poll(cx, None) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Ready(Ok(event)) => {
                        match event {
                            id::Progress::Initialized(_) => {
                                self.facts.borrow_mut().identity_initialized = true
                            }
                            id::Progress::Lost { report, cause } => {
                                let mut facts = self.facts.borrow_mut();
                                facts.identity_retired =
                                    Some((report.operations, report.exposed, report.egos));
                                facts.identity_cause = Some(cause);
                                return Poll::Ready(Err(
                                    "current IDENTITY monitor source was lost".into(),
                                ));
                            }
                            id::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
                            id::Progress::Deleted { ego, .. } | id::Progress::EgoRetired(ego)
                                if self.ego == Some(ego) =>
                            {
                                return Poll::Ready(Err(
                                    "original selected ego was deleted/retired".into(),
                                ));
                            }
                            id::Progress::ConnectRetry { error, .. } => {
                                self.facts.borrow_mut().retry("IDENTITY monitor", error)
                            }
                            id::Progress::Closed => {
                                return Poll::Ready(Err("current IDENTITY monitor closed".into()));
                            }
                            _ => {}
                        }
                        self.validate()?;
                        return Poll::Ready(Ok(()));
                    }
                },
                _ => match self.pils.poll_guarded(cx, None, &mut || Ok(())) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Ready(Ok(event)) => {
                        match event {
                            pils::Progress::Inbound(Inbound::Identity { identity, .. }) => {
                                let peer = *identity.peer().as_bytes();
                                if self
                                    .peer_epoch
                                    .is_some_and(|epoch| epoch != identity.epoch())
                                {
                                    return Poll::Ready(Err(
                                        "PILS replaced the original phone observer MQ".into(),
                                    ));
                                }
                                self.peer_deadline = if identity.expiration().is_never() {
                                    None
                                } else {
                                    Some(Box::pin(Deadline::at(
                                        self.pils.clock(),
                                        identity.expiration(),
                                    )?))
                                };
                                self.peer = Some(peer);
                                self.peer_epoch = Some(identity.epoch());
                                self.facts.borrow_mut().pils_observed = true;
                            }
                            pils::Progress::Lost { cause, report, .. } => {
                                let mut facts = self.facts.borrow_mut();
                                facts.pils_retained = report.retained();
                                facts.pils_cause = Some(cause);
                                return Poll::Ready(Err("original PILS source was lost".into()));
                            }
                            pils::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
                            pils::Progress::ConnectRetry { error, .. } => {
                                self.facts.borrow_mut().retry("PILS", error)
                            }
                            pils::Progress::Closed => {
                                return Poll::Ready(Err(
                                    "PILS closed without current identity".into()
                                ));
                            }
                            _ => {}
                        }
                        self.valid_peer()?;
                        self.validate()?;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
        Poll::Pending
    }
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(lookup) = &mut self.lookup
            && let Some(loss) = lookup.close()
        {
            self.facts.borrow_mut().identity_lookup_retired =
                Some((loss.operations, loss.exposed, loss.egos));
        }
        if let Some(loss) = self.monitor.close() {
            self.facts.borrow_mut().identity_retired =
                Some((loss.operations, loss.exposed, loss.egos));
        }
        self.facts.borrow_mut().pils_retired = self.pils.close().iter().flatten().count();
        self.secret = None;
    }
}
impl Drop for Sources<'_, '_> {
    fn drop(&mut self) {
        self.close();
    }
}
