//! PILS epoch binding, not a second PILS protocol/service or native MQ proof.
#![cfg(feature = "pils-client")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite ownership witnesses assert real signature/derived identity and explicit source loss."
)]
use gnunet_pils::{
    HelloLimits, MasterKey, Profile, Service,
    client::{Client, Instance, LocalKeyStatus},
};
use gnunet_types::Error;
use gnunet_udp_communicator_host::identity::IdentityEpoch;
use gnunet_wire::official::AbsoluteTime;
fn limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 1024,
        maximum_addresses: 16,
    }
}
#[test]
fn only_matched_current_pils_owner_can_borrow_udp_keys_and_real_loss_retires_binding()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut source = Client::<4, 1024, 2048>::new(&mut instance, Profile::Reference029, limits())?;
    let service = Service::<2048>::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        100,
        limits(),
    )?;
    assert!(matches!(
        IdentityEpoch::from_client(&source, AbsoluteTime::from_micros(100)),
        Err(Error::NotReady)
    ));
    let epoch = source.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut frame = service.announcement().to_vec();
    let _observation = source.receive(
        epoch,
        &mut frame,
        &mut [0; 1024],
        AbsoluteTime::from_micros(100),
    )?;
    assert_eq!(
        source.enable_local_key(MasterKey::from_seed([99; 32]))?,
        LocalKeyStatus::Mismatch
    );
    assert!(matches!(
        IdentityEpoch::from_client(&source, AbsoluteTime::from_micros(100)),
        Err(Error::NotReady)
    ));
    assert_eq!(
        source.enable_local_key(MasterKey::from_seed([17; 32]))?,
        LocalKeyStatus::Matched
    );
    let mut binding = IdentityEpoch::from_client(&source, AbsoluteTime::from_micros(100))?;
    let expiry = binding.observation().expiration();
    assert!(matches!(
        IdentityEpoch::from_client(&source, expiry),
        Err(Error::Timeout)
    ));
    assert!(matches!(
        binding.current_client(&source, expiry),
        Err(Error::Timeout)
    ));
    assert!(matches!(
        binding.refresh_client(&source, expiry),
        Err(Error::Timeout)
    ));
    assert_eq!(
        binding
            .current_client(&source, AbsoluteTime::from_micros(100))?
            .peer(),
        *service.identity().public_key().as_bytes()
    );
    assert!(matches!(
        binding.current_client(&source, AbsoluteTime::NEVER),
        Err(Error::Timeout)
    ));
    source.disable_local_key();
    assert!(matches!(
        binding.current_client(&source, AbsoluteTime::from_micros(100)),
        Err(Error::NotReady)
    ));
    source.enable_local_key(MasterKey::from_seed([17; 32]))?;
    source.connection_lost(epoch, AbsoluteTime::from_micros(1))?;
    assert!(matches!(
        binding.current_client(&source, AbsoluteTime::from_micros(100)),
        Err(Error::Stale)
    ));
    let next = source.next_wakeup().ok_or(Error::Stale)?;
    let replacement = source.begin_connection(next)?;
    let mut frame = service.announcement().to_vec();
    let _observation = source.receive(
        replacement,
        &mut frame,
        &mut [0; 1024],
        AbsoluteTime::from_micros(101),
    )?;
    assert_eq!(
        source.identity().ok_or(Error::NotReady)?.peer(),
        binding.observation().peer()
    );
    assert!(matches!(
        binding.current_client(&source, AbsoluteTime::from_micros(101)),
        Err(Error::Stale)
    ));
    binding.close();
    let new = IdentityEpoch::from_client(&source, AbsoluteTime::from_micros(101))?;
    assert_eq!(new.peer(), binding.peer());
    assert_ne!(new.observation().epoch(), binding.observation().epoch());
    Ok(())
}
#[test]
fn same_peer_from_another_branded_pils_client_and_duplicate_new_revision_are_stale()
-> Result<(), Error> {
    let mut first_instance = Instance::new();
    let mut second_instance = Instance::new();
    let mut first =
        Client::<4, 1024, 2048>::new(&mut first_instance, Profile::Reference029, limits())?;
    let mut second =
        Client::<4, 1024, 2048>::new(&mut second_instance, Profile::Reference029, limits())?;
    let service = Service::<2048>::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        100,
        limits(),
    )?;
    let epoch = first.begin_connection(AbsoluteTime::from_micros(0))?;
    let other = second.begin_connection(AbsoluteTime::from_micros(0))?;
    for (client, epoch) in [(&mut first, epoch), (&mut second, other)] {
        let mut frame = service.announcement().to_vec();
        let _observation = client.receive(
            epoch,
            &mut frame,
            &mut [0; 1024],
            AbsoluteTime::from_micros(100),
        )?;
        client.enable_local_key(MasterKey::from_seed([17; 32]))?;
    }
    let binding = IdentityEpoch::from_client(&first, AbsoluteTime::from_micros(100))?;
    assert!(matches!(
        binding.current_client(&second, AbsoluteTime::from_micros(100)),
        Err(Error::Stale)
    ));
    let mut frame = service.announcement().to_vec();
    let _observation = first.receive(
        epoch,
        &mut frame,
        &mut [0; 1024],
        AbsoluteTime::from_micros(101),
    )?;
    assert!(matches!(
        binding.current_client(&first, AbsoluteTime::from_micros(101)),
        Err(Error::Stale)
    ));
    Ok(())
}
