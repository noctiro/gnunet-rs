//! One additional public pure format model. No key, crypto, native, file or
//! backend provider is constructed. This handoff prepares source, not a run.
use gnunet_rest::{
    form::{Form, Limits},
    http,
    route::{self, Endpoint, Resolution},
};
use gnunet_types::Error;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public format assertions with fallible setup"
)]
fn forms_and_active_routes_remain_original_and_bounded() -> Result<(), Error> {
    let mut key = [0u8; 128];
    let mut out = [0u8; 128];
    let form = Form::new(
        b"application/x-www-form-urlencoded; charset=UTF-8",
        b"client_id=public&redirect_uri=https%3A%2F%2Fexample.invalid%2Frp-a&scope=openid+email",
        Limits::default(),
    )?;
    let n = form
        .get(b"redirect_uri", &mut key, &mut out)?
        .ok_or(Error::NotFound)?;
    assert_eq!(&out[..n], b"https://example.invalid/rp-a");
    assert!(matches!(
        Form::new(
            b"application/x-www-form-urlencoded",
            b"code=%00",
            Limits::default()
        ),
        Err(Error::Malformed | Error::InvalidInput)
    ));
    let body=b"preamble\r\n--public-boundary\r\nContent-Disposition: form-data; name=\"client_id\"\r\n\r\npublic\r\n--public-boundary\r\nContent-Disposition: form-data; name=\"code\"; filename=\"public\"\r\n\r\noriginal-code\r\n--public-boundary--\r\nepilogue";
    let form = Form::new(
        b"multipart/form-data; boundary=public-boundary",
        body,
        Limits::default(),
    )?;
    let n = form
        .get(b"code", &mut key, &mut out)?
        .ok_or(Error::NotFound)?;
    assert_eq!(&out[..n], b"original-code");
    let duplicate = Form::new(
        b"application/x-www-form-urlencoded",
        b"code=one&%63ode=two",
        Limits::default(),
    )?;
    assert!(matches!(
        duplicate.get(b"code", &mut key, &mut out),
        Err(Error::Conflict)
    ));
    let low = Limits {
        work: 1,
        ..Limits::default()
    };
    assert!(matches!(
        Form::new(b"multipart/form-data; boundary=public-boundary", body, low),
        Err(Error::Capacity)
    ));
    for (target, method, endpoint) in [
        (
            b"/config/REST".as_slice(),
            b"POST".as_slice(),
            Endpoint::ConfigPost,
        ),
        (b"/gns/public.example", b"GET", Endpoint::GnsGet),
        (b"/openid/authorize", b"POST", Endpoint::Authorize),
        (b"/openid/token", b"POST", Endpoint::Token),
        (b"/openid/userinfo", b"GET", Endpoint::Userinfo),
        (b"/jwks.json", b"GET", Endpoint::Jwks),
        (
            b"/.well-known/openid-configuration",
            b"GET",
            Endpoint::Discovery,
        ),
    ] {
        let mut input = Vec::new();
        input.extend_from_slice(method);
        input.extend_from_slice(b" ");
        input.extend_from_slice(target);
        input.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
        let request = http::Request::parse(&input, http::Limits::default())?;
        let mut path = [0u8; 128];
        assert!(
            matches!(route::resolve(&request,&mut path)?,Resolution::Found(route) if route.endpoint()==endpoint)
        );
    }
    Ok(())
}
