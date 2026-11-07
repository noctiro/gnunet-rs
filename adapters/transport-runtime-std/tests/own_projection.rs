//! Actual projection composition over real pure PILS frames/signatures. Commit
//! observations below are explicit lifecycle-port inputs, not filesystem proof.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check original record provenance, desired resources and exact signed values"
)]
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, Entropy};
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service, client as pc};
use gnunet_transport::{
    ClientId, Engine, Limits, PeerId, Signer,
    addresses::Publication,
    own::{
        Authority, Certificate, CommitOutcome, OfferId, PublicationBounds, REFRESH_FLOOR,
        RecordProvenance,
    },
    own_hello::HelloCandidate,
    own_wire,
};
use gnunet_transport_runtime::own::{ObservedAuthority, OwnedProjection, ProjectionLimits};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, SignaturePurpose, pils::Request};

type Owner<'a> = pc::Client<'a, 8, 1024, 2048>;
const A: &[u8] = b"tcp-127.0.0.1:2086";
const B: &[u8] = b"tcp-127.0.0.1:2087";
struct ValidationSigner(PeerId);
impl Signer for ValidationSigner {
    fn identity(&self) -> PeerId {
        self.0
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unavailable)
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(9);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..2].copy_from_slice(&(size as u16).to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    bytes
}
fn hello_limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 1024,
        maximum_addresses: 32,
    }
}
struct Fixture<'a> {
    client: Owner<'a>,
    epoch: pc::Epoch<'a>,
    service: Service<2048>,
    authority: ObservedAuthority<'a>,
    engine: Engine,
    communicator: ClientId,
    peer: PeerId,
    engine_time: u64,
    purposes: Vec<u32>,
}
impl<'a> Fixture<'a> {
    fn new(instance: &'a mut pc::Instance, seed: u8) -> Result<Self, Error> {
        let service = Service::new(
            MasterKey::from_seed([seed; 32]),
            Profile::Reference029,
            100,
            hello_limits(),
        )?;
        let peer = PeerId(*service.identity().public_key().as_bytes());
        let mut client = Owner::new(instance, Profile::Reference029, hello_limits())?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(0))?;
        let mut announcement = service.announcement().to_vec();
        let identity = match client.receive(
            epoch,
            &mut announcement,
            &mut [0; 1024],
            AbsoluteTime::from_micros(100),
        )? {
            pc::Inbound::Identity { identity, .. } => identity,
            _ => return Err(Error::Malformed),
        };
        let authority = ObservedAuthority::new(identity);
        let mut engine = Engine::new(peer, Limits::default())?;
        let communicator = engine.accept()?;
        let mut registration = frame(1211, 16);
        registration[4..8].copy_from_slice(&1_u32.to_be_bytes());
        registration[12..].copy_from_slice(b"tcp\0");
        engine.receive(
            &communicator,
            &registration,
            1,
            &mut ValidationSigner(peer),
            &mut Random,
        )?;
        Ok(Self {
            client,
            epoch,
            service,
            authority,
            engine,
            communicator,
            peer,
            engine_time: 1,
            purposes: Vec::new(),
        })
    }
    fn add(&mut self, address: &[u8]) -> Result<(), Error> {
        let mut bytes = frame(1200, address.len() + 21);
        bytes[8..16].copy_from_slice(&120_000_000_u64.to_be_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_be_bytes());
        bytes[20..20 + address.len()].copy_from_slice(address);
        self.engine_time += 1;
        self.engine.receive(
            &self.communicator,
            &bytes,
            self.engine_time,
            &mut ValidationSigner(self.peer),
            &mut Random,
        )?;
        Ok(())
    }
    fn certificate(&self, index: usize) -> Result<Certificate, Error> {
        Certificate::new(
            self.engine
                .local_addresses()
                .nth(index)
                .ok_or(Error::NotFound)?,
            self.authority.pure().clone(),
            4096,
        )
    }
    fn complete_signature(&mut self, now: u64) -> Result<(EddsaPublicKey, EddsaSignature), Error> {
        let mut request = [0; 1024];
        let tx = self
            .client
            .next_request(self.epoch, &mut request)?
            .ok_or(Error::NotReady)?;
        let purpose = match Request::decode(&request[..tx.len])? {
            Request::Sign { region, .. } => SignaturePurpose::decode(&region[..8])?.purpose(),
            _ => return Err(Error::Malformed),
        };
        self.purposes.push(purpose);
        self.client.written(self.epoch, tx.transmit)?;
        let mut response = [0; 104];
        let length =
            match self
                .service
                .receive(&request[..tx.len], &mut [0; 1024], now, &mut response)?
            {
                Action::Reply { len, .. } => len,
                _ => return Err(Error::Malformed),
            };
        match self.client.receive(
            self.epoch,
            &mut response[..length],
            &mut [0; 1024],
            AbsoluteTime::from_micros(now),
        )? {
            pc::Inbound::Complete(pc::Completion::Signature {
                operation,
                peer,
                signature,
                ..
            }) => {
                assert_eq!(operation, tx.operation);
                Ok((peer, signature))
            }
            _ => Err(Error::Authentication),
        }
    }
    fn sign_prepared(&mut self, certificate: &mut Certificate, now: u64) -> Result<OfferId, Error> {
        let offer = certificate.signature_offer().ok_or(Error::NotReady)?;
        let id = offer.id.clone();
        self.client.sign(
            offer.region,
            pc::KeyTarget::Exact(self.client.identity().ok_or(Error::NotReady)?),
        )?;
        certificate.signing_admitted(&id)?;
        let (peer, signature) = self.complete_signature(now)?;
        assert!(certificate.signed(&id, peer, signature)?);
        Ok(id)
    }
    fn sign_record(
        &mut self,
        certificate: &mut Certificate,
        now: u64,
        stamp: u64,
    ) -> Result<OfferId, Error> {
        certificate.prepare(now, stamp)?;
        self.sign_prepared(certificate, now)
    }
    fn sign_hello(&mut self, mut hello: HelloCandidate, now: u64) -> Result<HelloCandidate, Error> {
        let mut scratch = [0; 4096];
        let identity = self.client.identity().ok_or(Error::NotReady)?;
        let expiry = hello.expiry();
        hello.with_builder(&mut scratch, |builder| {
            self.client
                .sign_hello(builder, expiry, pc::KeyTarget::Exact(identity))
        })?;
        let id = hello.id().clone();
        hello.signing_admitted(&id)?;
        let (peer, signature) = self.complete_signature(now)?;
        assert!(hello.signed(&id, peer, signature, &mut scratch)?);
        Ok(hello)
    }
    fn hello(&mut self, now: u64) -> Result<HelloCandidate, Error> {
        let hello = prepare_hello(
            self.engine.address_snapshot()?,
            self.authority.pure().clone(),
            now,
        )?;
        self.sign_hello(hello, now)
    }
    fn project(
        &self,
        certificates: &[&Certificate],
        hello: &HelloCandidate,
        now: u64,
    ) -> Result<OwnedProjection, Error> {
        project(
            self.engine.address_snapshot()?,
            &self.authority,
            certificates,
            hello,
            now,
        )
    }
}
fn prepare_hello(
    set: Publication<'_>,
    authority: Authority,
    now: u64,
) -> Result<HelloCandidate, Error> {
    HelloCandidate::prepare(
        set,
        authority,
        now,
        PublicationBounds::checked(8, 4096, 65535, 65535)?,
        8,
    )
}
fn project(
    set: Publication<'_>,
    authority: &ObservedAuthority<'_>,
    certificates: &[&Certificate],
    hello: &HelloCandidate,
    now: u64,
) -> Result<OwnedProjection, Error> {
    OwnedProjection::copy_from(
        set,
        authority,
        certificates,
        hello,
        ProjectionLimits {
            records: 8,
            value_bytes: 4096,
            total_value_bytes: 16384,
        },
        now,
    )
}
fn committed(certificate: &mut Certificate, id: &OfferId, now: u64) -> Result<(), Error> {
    certificate.commit_started(id)?;
    assert!(matches!(
        certificate.commit_finished(id, CommitOutcome::Committed, now)?,
        gnunet_transport::own::CommitResult::Committed { retired: false, .. }
    ));
    Ok(())
}

#[test]
fn current_and_staged_members_compose_and_hello_only_renewal_resigns_no_address()
-> Result<(), Error> {
    let mut instance = pc::Instance::new();
    let mut f = Fixture::new(&mut instance, 17)?;
    f.add(A)?;
    let mut a = f.certificate(0)?;
    let a_id = f.sign_record(&mut a, 100, 1000)?;
    committed(&mut a, &a_id, 101)?;
    let a_value = a.current().ok_or(Error::NotReady)?.value.to_vec();
    assert!(a.signature_offer().is_none());
    f.add(B)?;
    let mut b = f.certificate(1)?;
    let b_id = f.sign_record(&mut b, 102, 1001)?;
    let mut hello = f.hello(103)?;
    let projection = f.project(&[&a, &b], &hello, 104)?;
    assert_eq!(projection.records().len(), 2);
    assert_eq!(
        projection.records()[0].provenance(),
        RecordProvenance::Committed
    );
    assert_eq!(
        projection.records()[1].provenance(),
        RecordProvenance::Staged
    );
    assert_eq!(projection.records()[0].offer(), &a_id);
    assert_eq!(projection.records()[1].offer(), &b_id);
    assert_eq!(projection.records()[0].value(), a_value);
    for row in projection.records() {
        own_wire::AddressRecord::parse(row.value())?.verify(f.authority.pure().peer())?;
    }
    committed(&mut b, &b_id, 105)?;
    let hello_id = hello.id().clone();
    hello.commit_started(&hello_id)?;
    hello.commit_finished(&hello_id, CommitOutcome::Committed)?;
    f.engine.refresh_address_publication()?;
    let renewed_hello = f.hello(106)?;
    let renewed = f.project(&[&a, &b], &renewed_hello, 107)?;
    assert!(
        renewed
            .records()
            .iter()
            .all(|r| r.provenance() == RecordProvenance::Committed)
    );
    assert_eq!(renewed.records()[0].offer(), &a_id);
    assert_eq!(renewed.records()[1].offer(), &b_id);
    assert_eq!(
        renewed.records()[0].value(),
        projection.records()[0].value()
    );
    assert_eq!(
        renewed.records()[1].value(),
        projection.records()[1].value()
    );
    assert!(a.pending_id().is_none() && b.pending_id().is_none());
    assert_eq!(f.purposes, [29, 29, 7, 7]);
    Ok(())
}

#[test]
fn expired_and_retired_current_values_are_history_without_publication_authority()
-> Result<(), Error> {
    let mut instance = pc::Instance::new();
    let mut f = Fixture::new(&mut instance, 17)?;
    f.add(A)?;
    let mut a = f.certificate(0)?;
    let id = f.sign_record(&mut a, 100, 1000)?;
    committed(&mut a, &id, 101)?;
    let hello = f.hello(102)?;
    let expiry = a.current().ok_or(Error::NotReady)?.expiry;
    assert!(f.project(&[&a], &hello, expiry - 1).is_ok());
    assert_eq!(f.project(&[&a], &hello, expiry).err(), Some(Error::Stale));
    a.retire();
    assert!(a.current().is_some());
    assert_eq!(f.project(&[&a], &hello, 103).err(), Some(Error::Stale));
    Ok(())
}

#[test]
fn pending_write_and_unknown_replacement_never_fall_back_to_valid_old_current() -> Result<(), Error>
{
    let mut instance = pc::Instance::new();
    let mut f = Fixture::new(&mut instance, 17)?;
    f.add(A)?;
    let mut a = f.certificate(0)?;
    let id = f.sign_record(&mut a, 100, 1000)?;
    committed(&mut a, &id, 101)?;
    let hello = f.hello(102)?;
    let now = 101 + REFRESH_FLOOR;
    a.prepare(now, 1001)?;
    assert_eq!(f.project(&[&a], &hello, now).err(), Some(Error::NotReady));
    let new = f.sign_prepared(&mut a, now)?;
    a.commit_started(&new)?;
    assert_eq!(
        f.project(&[&a], &hello, now + 1).err(),
        Some(Error::Conflict)
    );
    a.commit_finished(&new, CommitOutcome::Unknown(Error::Storage), now + 1)?;
    assert!(a.current().ok_or(Error::NotReady)?.expiry > now + 2);
    assert_eq!(
        f.project(&[&a], &hello, now + 2).err(),
        Some(Error::OutcomeUnknown)
    );
    a.recovered(&new, CommitOutcome::NotCommitted(Error::Storage), now + 3)?;
    let resumed = f.project(&[&a], &hello, now + 3)?;
    assert_eq!(resumed.records()[0].offer(), &id);
    assert_eq!(
        resumed.records()[0].provenance(),
        RecordProvenance::Committed
    );
    Ok(())
}

#[test]
fn desired_lease_and_authority_changes_cannot_relabel_a_committed_value() -> Result<(), Error> {
    let mut instance = pc::Instance::new();
    let mut f = Fixture::new(&mut instance, 17)?;
    f.add(A)?;
    let mut a = f.certificate(0)?;
    let id = f.sign_record(&mut a, 100, 1000)?;
    committed(&mut a, &id, 101)?;
    let different_brand = ObservedAuthority::new(f.client.identity().ok_or(Error::NotReady)?);
    let hello = prepare_hello(
        f.engine.address_snapshot()?,
        different_brand.pure().clone(),
        102,
    )?;
    let hello = f.sign_hello(hello, 102)?;
    assert_eq!(
        project(
            f.engine.address_snapshot()?,
            &different_brand,
            &[&a],
            &hello,
            103
        )
        .err(),
        Some(Error::Stale)
    );
    let mut other_instance = pc::Instance::new();
    let mut other = Fixture::new(&mut other_instance, 18)?;
    let hello = prepare_hello(
        f.engine.address_snapshot()?,
        other.authority.pure().clone(),
        103,
    )?;
    let hello = other.sign_hello(hello, 103)?;
    assert_eq!(
        project(
            f.engine.address_snapshot()?,
            &other.authority,
            &[&a],
            &hello,
            104
        )
        .err(),
        Some(Error::Stale)
    );
    f.engine_time += 1;
    f.engine.receive(
        &f.communicator,
        &frame(1201, 8),
        f.engine_time,
        &mut ValidationSigner(f.peer),
        &mut Random,
    )?;
    f.add(A)?;
    assert!(!f.engine.owns_local_address(a.lease()));
    let replacement_hello = f.hello(105)?;
    assert_eq!(
        f.project(&[&a], &replacement_hello, 106).err(),
        Some(Error::Stale)
    );
    Ok(())
}

#[test]
fn actual_journal_backend_keeps_refused_original_and_commits_mixed_then_hello_only_projection()
-> Result<(), Error> {
    use gnunet_transport_host::peerstore::{Journal, ManagedQuota};
    use gnunet_transport_runtime::{own::OwnRecordBackend, own_store::JournalBackend};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| Error::Entropy)?;
    let path = std::env::temp_dir().join(format!(
        "gnunet-own-backend-{:032x}",
        u128::from_be_bytes(random)
    ));
    std::fs::create_dir(&path).map_err(|_| Error::Storage)?;
    let directory = Cleanup(path);
    let mut journal = Journal::open(directory.0.join("db"))?;
    assert_eq!(journal.reserve_monotime(1000, 10)?, (1000, 1009));
    let mut instance = pc::Instance::new();
    let mut f = Fixture::new(&mut instance, 17)?;
    f.add(A)?;
    let mut a = f.certificate(0)?;
    let a_id = f.sign_record(&mut a, 100, 1000)?;
    let mut hello = f.hello(101)?;
    let hello_id = hello.id().clone();
    let projection = f.project(&[&a], &hello, 102)?;
    let refused = match JournalBackend::at(&mut journal, 102).prepare_own(projection) {
        Ok(_unexpected) => return Err(Error::Malformed),
        Err(original) => original,
    };
    assert_eq!(refused.cause, Error::Unavailable);
    assert_eq!(refused.original.records()[0].offer(), &a_id);
    assert_eq!(refused.original.hello_offer(), &hello_id);
    assert!(!journal.transaction_pending());
    journal.reserve_managed(ManagedQuota {
        records: 3,
        bytes: 16384,
    })?;
    let mut backend = JournalBackend::at(&mut journal, 102);
    let mut original = backend.prepare_own(refused.original).map_err(|r| r.cause)?;
    assert_eq!(
        backend.abort_own(&mut original)?,
        CommitOutcome::NotCommitted(Error::Cancelled)
    );
    assert_eq!(original.projection().records()[0].offer(), &a_id);
    drop(original);
    // Before any pure commit admission, a known pre-I/O abort permits copying
    // the same verified originals again without another purpose29 signature.
    let projection = f.project(&[&a], &hello, 102)?;
    let mut original = backend.prepare_own(projection).map_err(|r| r.cause)?;
    a.commit_started(&a_id)?;
    hello.commit_started(&hello_id)?;
    let outcome = backend.commit_own(&mut original);
    assert_eq!(outcome, CommitOutcome::Committed);
    assert!(backend.own_io_quiescent(&original));
    assert!(original.failure().is_none());
    a.commit_finished(&a_id, outcome, 103)?;
    hello.commit_finished(&hello_id, outcome)?;
    assert_eq!(original.projection().records()[0].offer(), &a_id);
    let a_value = a.current().ok_or(Error::NotReady)?.value.to_vec();
    drop(original);
    f.add(B)?;
    let mut b = f.certificate(1)?;
    let b_id = f.sign_record(&mut b, 104, 1001)?;
    let mut hello = f.hello(105)?;
    let hello_id = hello.id().clone();
    let projection = f.project(&[&a, &b], &hello, 106)?;
    assert_eq!(
        projection.records()[0].provenance(),
        RecordProvenance::Committed
    );
    assert_eq!(
        projection.records()[1].provenance(),
        RecordProvenance::Staged
    );
    let mut backend = JournalBackend::at(&mut journal, 106);
    let mut original = backend.prepare_own(projection).map_err(|r| r.cause)?;
    b.commit_started(&b_id)?;
    hello.commit_started(&hello_id)?;
    let outcome = backend.commit_own(&mut original);
    assert_eq!(outcome, CommitOutcome::Committed);
    b.commit_finished(&b_id, outcome, 107)?;
    hello.commit_finished(&hello_id, outcome)?;
    assert_eq!(a.current().ok_or(Error::NotReady)?.value, a_value);
    assert!(a.pending_id().is_none());
    drop(original);
    f.engine.refresh_address_publication()?;
    let mut hello = f.hello(108)?;
    let hello_id = hello.id().clone();
    let projection = f.project(&[&a, &b], &hello, 109)?;
    assert!(
        projection
            .records()
            .iter()
            .all(|r| r.provenance() == RecordProvenance::Committed)
    );
    let mut backend = JournalBackend::at(&mut journal, 109);
    let mut original = backend.prepare_own(projection).map_err(|r| r.cause)?;
    hello.commit_started(&hello_id)?;
    let outcome = backend.commit_own(&mut original);
    assert_eq!(outcome, CommitOutcome::Committed);
    hello.commit_finished(&hello_id, outcome)?;
    assert!(a.pending_id().is_none() && b.pending_id().is_none());
    assert_eq!(f.purposes, [29, 7, 29, 7, 7]);
    assert_eq!(original.outcome(), Some(CommitOutcome::Committed));
    drop(original);
    assert_eq!(journal.commits(), 4);
    drop(journal);
    let journal = Journal::open(directory.0.join("db"))?;
    assert_eq!(journal.highwater(), 1009);
    let raw = std::fs::read(directory.0.join("db")).map_err(|_| Error::Storage)?;
    assert!(raw.windows(a_value.len()).any(|bytes| bytes == a_value));
    let b_value = b.current().ok_or(Error::NotReady)?.value;
    assert!(raw.windows(b_value.len()).any(|bytes| bytes == b_value));
    Ok(())
}
