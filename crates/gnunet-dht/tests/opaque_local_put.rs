//! Unexecuted source cases for local opaque forwarding and validation boundaries.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions inspect actual fallible owner transitions; this source does not claim an execution result"
)]
use gnunet_block::{ReplyEvaluation, bloom::NativeEndian};
use gnunet_crypto::Entropy;
use gnunet_dht::{
    network::{Filter, Job, JobKind, NetworkBlocks, NetworkOwner, Peer, Policy, Work},
    routing::Estimate,
    service::{Blocks, Instance, Limits, LocalOwner, Outcome, TypeCapability, Validity},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{PutMessage, RouteOptions, ipc::Put},
};
const KIND: u32 = 65000;
struct Registry {
    capability: Result<TypeCapability, Error>,
    validity: Validity,
    validations: usize,
}
impl Registry {
    fn absent() -> Self {
        Self {
            capability: Ok(TypeCapability::Absent),
            validity: Validity::Invalid,
            validations: 0,
        }
    }
}
impl Blocks for Registry {
    fn type_capability(&self, _: u32) -> Result<TypeCapability, Error> {
        self.capability
    }
    fn query(&mut self, _: u32, _: &[u8; 64], _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn validate(&mut self, _: u32, _: &[u8; 64], _: &[u8], _: u64) -> Result<Validity, Error> {
        self.validations += 1;
        Ok(self.validity)
    }
    fn reply(
        &mut self,
        _: u32,
        _: &[u8; 64],
        _: &[u8],
        _: u32,
        _: &[u8],
        _: u64,
    ) -> Result<ReplyEvaluation, Error> {
        Err(Error::Unsupported)
    }
}
impl NetworkBlocks for Registry {
    fn derive_key(&mut self, _: u32, _: &[u8], _: u64) -> Result<Option<[u8; 64]>, Error> {
        Err(Error::Unsupported)
    }
    fn filter(
        &mut self,
        _: u32,
        _: Option<&[u8]>,
        _: usize,
        _: u32,
        _: NativeEndian,
    ) -> Result<Filter, Error> {
        Err(Error::Unsupported)
    }
    fn filtered_reply(
        &mut self,
        _: u32,
        _: &[u8; 64],
        _: &[u8],
        _: u32,
        _: &[u8],
        _: u64,
        _: &mut Filter,
    ) -> Result<ReplyEvaluation, Error> {
        Err(Error::Unsupported)
    }
}
struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Entropy)
    }
}
fn owner(instance: &mut Instance) -> Result<NetworkOwner<'_>, Error> {
    NetworkOwner::new(
        LocalOwner::new(instance, Limits::default())?,
        [1; 32],
        gnunet_dht::network::Limits::default(),
        Policy {
            estimate: Estimate::new(1.0)?,
        },
    )
}
fn frame(kind: u32) -> Result<Vec<u8>, Error> {
    frame_with_options(kind, 1)
}
fn frame_with_options(kind: u32, options: u32) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; 88 + b"opaque bytes".len()];
    Put {
        block_type: kind,
        options,
        replication: 1,
        expiration: AbsoluteTime::from_micros(10_000_000),
        key: &[3; 64],
        payload: b"opaque bytes",
    }
    .encode(&mut bytes)?;
    Ok(bytes)
}
fn outgoing<'id>(owner: &NetworkOwner<'id>) -> Result<(Job<'id>, Peer<'id>), Error> {
    for work in owner.work() {
        if let Work::Send {
            job,
            peer,
            kind: JobKind::Put,
            frame,
            ..
        } = work
        {
            let put = PutMessage::decode(frame)?;
            assert_eq!(put.block_type, KIND);
            assert_eq!(put.key, &[3; 64]);
            assert_eq!(put.payload, b"opaque bytes");
            assert_eq!(put.expiration.as_micros(), 10_000_000);
            assert_eq!(put.options, RouteOptions::DEMULTIPLEX_EVERYWHERE);
            assert_eq!(put.desired_replication_level, 1);
            assert_eq!(put.hop_count, 1);
            return Ok((job, peer));
        }
    }
    Err(Error::NotFound)
}
#[test]
fn absent_initial_put_transits_without_cache_or_send_receipt() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance)?;
    let client = owner.connect_client()?;
    owner.connect_peer([2; 32])?;
    let mut blocks = Registry::absent();
    assert_eq!(
        owner.ingest_client(client, &frame(KIND)?, 10, &mut blocks, &mut NoEntropy)?,
        Outcome::OpaquePut
    );
    assert_eq!(blocks.validations, 0);
    assert_eq!(owner.local_snapshot().cache_records, 0);
    assert_eq!(owner.local_snapshot().output_frames, 0);
    let before = owner.put_stats();
    assert_eq!(before.accepted, 1);
    assert_eq!(before.submitted, 0);
    assert_eq!(before.retained, 1);
    let (job, peer) = outgoing(&owner)?;
    owner.disconnect_client(client)?;
    assert_eq!(owner.put_stats().retained, 1);
    owner.admitted(job, peer)?;
    assert_eq!(owner.put_stats().submitted, 1);
    assert_eq!(owner.put_stats().retained, 0);
    owner.tick(5_000_020, &mut blocks, &mut NoEntropy)?;
    assert!(owner.work().next().is_none());
    Ok(())
}
#[test]
fn absent_unrouted_retry_keeps_original_payload_expiry_and_intent() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance)?;
    let client = owner.connect_client()?;
    let mut blocks = Registry::absent();
    owner.ingest_client(client, &frame(KIND)?, 10, &mut blocks, &mut NoEntropy)?;
    let original = owner.unrouted_puts().next().ok_or(Error::NotFound)?;
    assert!(owner.work().next().is_none());
    owner.connect_peer([2; 32])?;
    owner.tick(20, &mut blocks, &mut NoEntropy)?;
    let retained = owner.unrouted_puts().next().ok_or(Error::NotFound)?;
    assert_eq!(retained.put, original.put);
    assert_eq!(retained.accepted, original.accepted);
    assert_eq!(retained.expiration, original.expiration);
    assert_eq!(retained.until, original.until);
    assert_eq!(blocks.validations, 0);
    assert_eq!(owner.local_snapshot().cache_records, 0);
    let (job, peer) = outgoing(&owner)?;
    owner.admitted(job, peer)?;
    assert_eq!(owner.put_stats().retained, 0);
    owner.tick(5_000_020, &mut blocks, &mut NoEntropy)?;
    assert!(owner.work().next().is_none());
    Ok(())
}
#[test]
fn installed_invalid_provider_error_and_any_cannot_gain_opaque_permission() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance)?;
    let client = owner.connect_client()?;
    let mut blocks = Registry {
        capability: Ok(TypeCapability::Installed),
        validity: Validity::Invalid,
        validations: 0,
    };
    assert_eq!(
        owner.ingest_client(client, &frame(KIND)?, 10, &mut blocks, &mut NoEntropy),
        Err(Error::Authentication)
    );
    assert_eq!(blocks.validations, 1);
    assert_eq!(owner.put_stats().accepted, 0);
    assert!(owner.work().next().is_none());
    blocks.capability = Err(Error::WouldBlock);
    assert_eq!(
        owner.ingest_client(client, &frame(KIND)?, 10, &mut blocks, &mut NoEntropy),
        Err(Error::WouldBlock)
    );
    blocks.capability = Ok(TypeCapability::Absent);
    assert_eq!(
        owner.ingest_client(client, &frame(0)?, 10, &mut blocks, &mut NoEntropy),
        Err(Error::InvalidInput)
    );
    owner.ingest_client(client, &frame(KIND)?, 10, &mut blocks, &mut NoEntropy)?;
    blocks.capability = Ok(TypeCapability::Installed);
    owner.connect_peer([2; 32])?;
    owner.tick(20, &mut blocks, &mut NoEntropy)?;
    let failure = owner.take_unrouted_failure().ok_or(Error::NotFound)?;
    assert_eq!(failure.reason, Error::Authentication);
    assert_eq!(owner.put_stats().retained, 0);
    assert_eq!(owner.put_stats().submitted, 0);
    assert!(owner.work().next().is_none());
    assert_eq!(owner.local_snapshot().cache_records, 0);
    Ok(())
}

#[test]
fn indexed_job_membership_preserves_foreign_brand_holes_and_signing_tombstones() -> Result<(), Error>
{
    let mut first_instance = Instance::new();
    let mut second_instance = Instance::new();
    let mut first = owner(&mut first_instance)?;
    let mut second = owner(&mut second_instance)?;
    let client = first.connect_client()?;
    let foreign_client = second.connect_client()?;
    first.connect_peer([2; 32])?;
    second.connect_peer([2; 32])?;
    let mut blocks = Registry::absent();
    let bytes = frame(KIND)?;
    for _ in 0..128 {
        first.ingest_client(client, &bytes, 10, &mut blocks, &mut NoEntropy)?;
    }
    second.ingest_client(foreign_client, &bytes, 10, &mut blocks, &mut NoEntropy)?;
    let originals: Vec<_> = first.jobs().map(|info| info.job).collect();
    assert_eq!(originals.len(), 128);
    let (foreign, _) = outgoing(&second)?;
    assert_eq!(foreign.diagnostic(), originals[0].diagnostic());
    assert_ne!(foreign, originals[0]);
    assert!(!first.owns_job(foreign));
    assert!(first.job_info(foreign).is_none());
    assert_eq!(first.cancel_job(foreign), Err(Error::InvalidInput));
    assert_eq!(first.snapshot().jobs, 128);

    // Retire genuine alternating rows, then admit new intents across the
    // resulting serial gaps. No serial can recreate a canceled capability.
    for &job in originals.iter().step_by(2) {
        first.cancel_job(job)?;
    }
    for _ in 0..64 {
        first.ingest_client(client, &bytes, 20, &mut blocks, &mut NoEntropy)?;
    }
    assert_eq!(first.snapshot().jobs, 128);
    for (index, &job) in originals.iter().enumerate() {
        assert_eq!(first.owns_job(job), index % 2 != 0);
        assert_eq!(first.job_info(job).is_some(), index % 2 != 0);
    }
    assert_eq!(first.cancel_job(originals[0]), Err(Error::Stale));
    for info in first.jobs() {
        let found = first.job_info(info.job).ok_or(Error::NotFound)?;
        assert_eq!(found.job, info.job);
        assert_eq!(found.peer, info.peer);
        assert_eq!(found.until, info.until);
        assert_eq!(found.put, info.put);
        assert!(!found.issued && !found.retiring);
    }

    let tracked = frame_with_options(KIND, u32::from(RouteOptions::RECORD_ROUTE.bits()))?;
    first.ingest_client(client, &tracked, 30, &mut blocks, &mut NoEntropy)?;
    let signing = first
        .work()
        .find_map(|work| match work {
            Work::Sign { job, .. } => Some(job),
            _ => None,
        })
        .ok_or(Error::NotFound)?;
    let original = first.job_info(signing).ok_or(Error::NotFound)?;
    assert!(original.put.is_some());
    // These are explicit pure-owner caller inputs, not native PILS evidence.
    first.sign_started(signing)?;
    first.cancel_job(signing)?;
    assert!(first.owns_job(signing));
    let tombstone = first.job_info(signing).ok_or(Error::NotFound)?;
    assert!(tombstone.issued && tombstone.retiring);
    assert_eq!(tombstone.until, original.until);
    assert_eq!(tombstone.put, original.put);
    assert!(
        first
            .work()
            .any(|work| matches!(work, Work::Retire { job, .. } if job == signing))
    );
    assert_eq!(first.retired(foreign), Err(Error::InvalidInput));
    first.close();
    assert_eq!(first.snapshot().jobs, 1);
    assert!(first.owns_job(signing));
    first.retired(signing)?;
    assert!(!first.owns_job(signing));
    assert!(first.job_info(signing).is_none());
    assert_eq!(first.retired(signing), Err(Error::Stale));
    assert_eq!(first.snapshot().jobs, 0);
    Ok(())
}
