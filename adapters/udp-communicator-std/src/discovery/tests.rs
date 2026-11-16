//! Signed numeric address fixtures only; no LAN packets or native interfaces.
use super::*;

#[test]
fn snapshot_refresh_preserves_retry_bounds_and_unresolved_memberships() -> Result<(), Error> {
    let mut state = State::new(Configuration {
        interfaces: 2,
        ..Configuration::default()
    })?;
    let original = Interface {
        source: "[fd00::7]:0".parse().map_err(|_| Error::Malformed)?,
        index: 7,
        broadcast: None,
    };
    state.update(&[original], 100)?;
    state.rows[0].due = 2000;
    state.rows[0].join_due = 1000;
    state.memberships.push(Membership {
        index: 8,
        retry: 3000,
    });
    state.update(&[original], 500)?;
    if state.rows[0].due != 2000
        || state.rows[0].join_due != 1000
        || state.next_wakeup(500) != Some(1000)
        || state.update(&[original, original], 500) != Err(Error::Conflict)
        || state.rows[0].due != 2000
        || state.rows[0].join_due != 1000
    {
        return Err(Error::Conflict);
    }
    let replacement = Interface {
        index: 9,
        ..original
    };
    state.update(&[replacement], 500)?;
    if state.rows[0].due != 500
        || state.rows[0].join_due != 500
        || state.memberships.len() != 1
        || state.memberships[0].index != 8
        || state.memberships[0].retry != 3000
        || state.next_wakeup(500) != Some(3000)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn producer_profiles_verify_without_changing_the_observed_address() -> Result<(), Error> {
    let identity = Identity::from_seed([7; 32]);
    let local = Identity::from_seed([9; 32]);
    let profiles = [
        Profile::linux(Endian::Little),
        Profile::linux(Endian::Big),
        Profile::darwin(Endian::Little),
        Profile::darwin(Endian::Big),
        Profile::freebsd(Endian::Little),
        Profile::freebsd(Endian::Big),
        Profile::windows(Endian::Little),
        Profile::windows(Endian::Big),
    ];
    for address in [
        "192.0.2.7:1234".parse().map_err(|_| Error::Malformed)?,
        SocketAddrV6::new(
            "fd00::7".parse().map_err(|_| Error::Malformed)?,
            1234,
            0x1234,
            7,
        )
        .into(),
    ] {
        for profile in profiles {
            let packet = identity.broadcast(&address_hash(address, profile)?)?;
            let mut bytes = [0; 96];
            packet.encode(&mut bytes)?;
            if verify(&bytes, address, local.peer())? != Some(identity.peer()) {
                return Err(Error::Conflict);
            }
            let mut other = address;
            other.set_ip(if address.is_ipv4() {
                "192.0.2.8".parse().map_err(|_| Error::Malformed)?
            } else {
                "fd00::8".parse().map_err(|_| Error::Malformed)?
            });
            if verify(&bytes, other, local.peer()) != Err(Error::Authentication) {
                return Err(Error::Conflict);
            }
            if let SocketAddr::V6(mut other) = address {
                other.set_scope_id(8);
                if verify(&bytes, other.into(), local.peer()) != Err(Error::Authentication) {
                    return Err(Error::Conflict);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn native_state_uses_the_platform_sockaddr_profile_without_socket_io() -> Result<(), Error> {
    let mut state = State::new(Configuration::default())?;
    let source = "192.0.2.7:1234".parse().map_err(|_| Error::Malformed)?;
    state.update(
        &[Interface {
            source,
            index: 7,
            broadcast: Some(Ipv4Addr::new(192, 0, 2, 255)),
        }],
        100,
    )?;
    let identity = Identity::from_seed([7; 32]);
    let bytes = state.packet(0, &identity)?;
    let packet = Broadcast::decode(&bytes)?;
    packet.verify(&address_hash(source, native_profile()?)?)?;
    if state.packet(0, &identity)? != bytes {
        return Err(Error::Conflict);
    }
    Ok(())
}
