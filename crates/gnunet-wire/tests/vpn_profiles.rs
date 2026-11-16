//! Native C AF identifiers stay explicit; packet length never guesses a peer ABI.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Check independent native AF byte vectors and cross-profile refusal"
)]
use gnunet_types::Error;
use gnunet_wire::official::vpn::{Address, AfProfile, Request};

#[test]
fn native_platform_profiles_preserve_exact_ipv6_request_bytes() -> Result<(), Error> {
    for (profile, tag) in [
        (AfProfile::LINUX, 10u8),
        (AfProfile::DARWIN, 30),
        (AfProfile::FREEBSD, 28),
        (AfProfile::WINDOWS, 23),
    ] {
        let mut native = [0; 48];
        native[..4].copy_from_slice(&[0, 48, 0, 202]);
        native[15] = 1; // Absolute expiration in network order.
        native[19] = tag; // Requested result family.
        native[23] = tag; // Internet destination family.
        native[24..32].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        native[47] = 1; // ::1
        let request = Request::decode_with_profile(&native, profile)?;
        assert!(matches!(request, Request::Internet {
            reserved: 0, expires: 1, result_af, destination: Address::V6(address), request_id,
        } if result_af == u32::from(tag) && address == core::net::Ipv6Addr::LOCALHOST.octets()
            && request_id == [8,7,6,5,4,3,2,1]));
        let mut encoded = [0xa5; 48];
        assert_eq!(request.encode_with_profile(&mut encoded, profile)?, 48);
        assert_eq!(encoded, native);
        for other in [
            AfProfile::LINUX,
            AfProfile::DARWIN,
            AfProfile::FREEBSD,
            AfProfile::WINDOWS,
        ] {
            if other != profile {
                assert_eq!(
                    Request::decode_with_profile(&native, other),
                    Err(Error::Unsupported)
                );
            }
        }
    }
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "windows"
))]
mod native_default {
    use super::*;
    // Expected values come from the respective native C socket headers.
    #[cfg(target_os = "linux")]
    const IPV6: u8 = 10;
    #[cfg(target_vendor = "apple")]
    const IPV6: u8 = 30;
    #[cfg(target_os = "freebsd")]
    const IPV6: u8 = 28;
    #[cfg(target_os = "windows")]
    const IPV6: u8 = 23;

    #[test]
    fn default_codec_accepts_the_native_c_ipv6_frame() -> Result<(), Error> {
        let mut frame = [0u8; 48];
        frame[..4].copy_from_slice(&[0, 48, 0, 202]);
        frame[23] = IPV6;
        frame[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        frame[47] = 1;
        let request = Request::decode(&frame)?;
        assert!(
            matches!(request, Request::Internet { destination: Address::V6(address), .. }
            if address == core::net::Ipv6Addr::LOCALHOST.octets())
        );
        let mut encoded = [0xa5; 48];
        assert_eq!(request.encode(&mut encoded)?, 48);
        assert_eq!(encoded, frame);
        Ok(())
    }
}
