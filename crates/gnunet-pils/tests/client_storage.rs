//! Optional native storage and phased MQ retirement without changing wire/owner rules.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible storage/lifecycle regressions assert independent protocol and capacity facts"
)]
use gnunet_pils::{
    HelloLimits, MasterKey, Profile, Service,
    client::{
        ByteStorage, Client, HeapBytes, HeapClient, Inbound, Instance, KeyTarget, LocalKeyStatus,
    },
};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, SignaturePurpose};
fn limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 64,
    }
}
#[test]
fn exact_native_backing_handles_full_wire_request_without_embedding_payload_arrays()
-> Result<(), Error> {
    assert!(
        core::mem::size_of::<HeapClient<'_, 32>>()
            < core::mem::size_of::<Client<'_, 32, 65535, 65535>>()
    );
    assert!(HeapBytes::zeroed(usize::MAX).is_err());
    let mut instance = Instance::new();
    let mut client = HeapClient::<4>::new(&mut instance, Profile::Reference029, limits())?;
    let mut region = vec![0x41; 65527];
    SignaturePurpose::new(35, 65519)?.encode(&mut region)?;
    let id = client.sign(&region, KeyTarget::ServiceCurrent)?;
    let epoch = client.begin_connection(AbsoluteTime::from_micros(0))?;
    assert_eq!(client.next_request_len(epoch)?, Some(65535));
    let mut frame = vec![0; 65535];
    let tx = client
        .next_request(epoch, &mut frame)?
        .ok_or(Error::NotReady)?;
    assert_eq!(tx.operation, id);
    assert_eq!(tx.len, 65535);
    assert_eq!(&frame[..2], &u16::MAX.to_be_bytes());
    assert_eq!(&frame[8..], region.as_slice());
    assert_eq!(client.next_request_len(epoch)?, None);
    client.written(epoch, tx.transmit)?;
    let mut service = Service::<4096>::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        100,
        limits(),
    )?;
    let mut reply = [0; 104];
    service.receive(&frame, &mut [], 100, &mut reply)?;
    match client.receive(epoch, &mut reply, &mut [], AbsoluteTime::from_micros(100))? {
        Inbound::Complete(gnunet_pils::client::Completion::Signature {
            peer, signature, ..
        }) => peer.verify(35, &region, &signature)?,
        _ => return Err(Error::Malformed),
    }
    assert_eq!(reply, [0; 104]);
    assert_eq!(client.pending(), 0);
    Ok(())
}
#[test]
fn phased_loss_revokes_old_authority_before_retry_clock_registration() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut client = HeapClient::<4>::new(&mut instance, Profile::Reference029, limits())?;
    client.enable_local_key(MasterKey::from_seed([17; 32]))?;
    let service = Service::<4096>::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        100,
        limits(),
    )?;
    let epoch = client.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut announcement = service.announcement().to_vec();
    client.receive(
        epoch,
        &mut announcement,
        &mut [0; 4096],
        AbsoluteTime::from_micros(100),
    )?;
    let old = client.identity().ok_or(Error::NotReady)?;
    let operation = client.ecdh([7; 32], KeyTarget::Exact(old))?;
    let mut frame = [0; 40];
    let tx = client
        .next_request(epoch, &mut frame)?
        .ok_or(Error::NotReady)?;
    let report = client.prepare_connection_lost(epoch)?;
    assert_eq!(report.retained(), 1);
    assert!(client.identity().is_none() && client.local_key().is_none());
    assert_eq!(client.local_key_status(), LocalKeyStatus::Waiting);
    assert!(client.retry_registration_pending());
    assert_eq!(client.next_wakeup(), None);
    assert!(!client.connection_needed(AbsoluteTime::from_micros(u64::MAX)));
    assert_eq!(
        client.begin_connection(AbsoluteTime::from_micros(u64::MAX)),
        Err(Error::NotReady)
    );
    assert_eq!(
        client.ecdh([7; 32], KeyTarget::Exact(old)),
        Err(Error::Stale)
    );
    client.register_retry(AbsoluteTime::from_micros(100))?;
    assert!(!client.retry_registration_pending());
    assert!(client.connection_needed(AbsoluteTime::from_micros(0)));
    let new = client.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut replay = [0; 40];
    let retried = client
        .next_request(new, &mut replay)?
        .ok_or(Error::NotReady)?;
    assert_eq!(retried.operation, operation);
    assert_eq!(frame, replay);
    assert_ne!(retried.transmit, tx.transmit);
    assert_eq!(client.written(new, tx.transmit), Err(Error::Stale));
    Ok(())
}
