use super::*;
use gnunet_native::interfaces::InterfaceState;

fn row(name: &[u8], index: u32, address: std::net::SocketAddr) -> InterfaceAddress {
    InterfaceAddress {
        name: name.to_vec(),
        index,
        state: InterfaceState::UnixFlags(0),
        address,
        netmask: None,
    }
}

#[test]
fn a_new_or_rebound_address_cannot_inherit_the_original_state_sweep() -> io::Result<()> {
    let address = std::net::SocketAddr::from(([192, 0, 2, 1], 0));
    let original = Scope::new(vec![row(b"em0", 2, address)]);
    for changed in [
        Vec::new(),
        vec![row(b"em0", 3, address)],
        vec![row(b"em1", 2, address)],
        vec![row(b"em0", 2, address), row(b"em1", 3, address)],
    ] {
        if original.require_same(&Scope::new(changed)).is_ok() {
            return Err(io::Error::other("changed interface scope was adopted"));
        }
    }
    original.require_same(&Scope::new(vec![row(b"em0", 2, address)]))
}

#[test]
fn ordering_duplicates_and_link_flags_do_not_revoke_an_unchanged_address_scope() -> io::Result<()> {
    let a = row(b"em0", 2, std::net::SocketAddr::from(([192, 0, 2, 1], 0)));
    let b = row(b"lo0", 1, std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let original = Scope::new(vec![a.clone(), b.clone()]);
    let mut up = a.clone();
    up.state = InterfaceState::UnixFlags(libc::IFF_UP as u32);
    original.require_same(&Scope::new(vec![b, up, a]))
}
