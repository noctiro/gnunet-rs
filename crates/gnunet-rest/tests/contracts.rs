//! One public pure aggregate model, source-only in this handoff.
use gnunet_rest::{
    contracts,
    http::{Limits, Request, Response},
    route::{self, Endpoint, Resolution},
    text,
};
use gnunet_types::Error;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public framing/contract assertions with fallible setup"
)]
fn original_http_prefix_chunks_routes_and_contracts() -> Result<(), Error> {
    let complete=b"POST /identity HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n7;note=\"ok\"\r\n{\"name\"\r\n8\r\n:\"demo\"}\r\n0\r\nX-Diagnostic: public\r\n\r\nGET /copying HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let limits = Limits::default();
    let request = Request::parse(complete, limits)?;
    let next = &complete[request.consumed()..];
    assert!(next.starts_with(b"GET /copying"));
    let mut body = [0; 128];
    let n = request.body().decode(&mut body)?;
    assert_eq!(&body[..n], b"{\"name\":\"demo\"}");
    let mut path = [0; 2048];
    assert!(
        matches!(route::resolve(&request,&mut path)?,Resolution::Found(r) if r.endpoint()==Endpoint::IdentityCreate)
    );
    let mut payload = [0; 128];
    let mut tokens = [gnunet_json::Token::EMPTY; 16];
    let mut stack = [gnunet_json::Nest::EMPTY; 8];
    let mut json = gnunet_json::Workspace::new(&mut payload, &mut tokens, &mut stack);
    let doc = json.parse(
        &body[..n],
        gnunet_json::Limits {
            bytes: 128,
            nodes: 16,
            depth: 8,
            work: 1024,
        },
    )?;
    assert!(
        contracts::IdentityCreate::parse(doc.root())?
            .name
            .eq_ascii(b"demo")
    );
    assert!(matches!(Request::parse(b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",limits),Err(Error::Malformed)));
    assert!(matches!(
        Request::parse(
            b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\nx",
            limits
        ),
        Err(Error::Truncated)
    ));
    let query = route::Query::new(b"data=%FF%0A+raw");
    let mut key = [0; 32];
    let mut value = [0; 32];
    let n = query
        .get_bytes(b"data", &mut key, &mut value)?
        .ok_or(Error::NotFound)?;
    assert_eq!(&value[..n], b"\xff\n raw");
    assert!(matches!(
        route::Query::new(b"private=1&%70rivate=0").get(b"private", &mut key, &mut value),
        Err(Error::Conflict)
    ));
    let mut encoded = [0; 16];
    let n = text::encode(b"public", &mut encoded)?;
    let mut decoded = [0; 6];
    text::decode(&encoded[..n], &mut decoded)?;
    assert_eq!(&decoded, b"public");
    let response = Response {
        status: 204,
        body: &[],
        content_type: b"application/json",
        head_only: false,
        headers: &[],
    };
    let mut wire = [0; 256];
    let n = response.encode(&mut wire)?;
    assert!(!wire[..n].windows(15).any(|b| b == b"Content-Length:"));
    Ok(())
}

/// Public nonsecret static request bytes only; no native HTTP actor or backend.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure original-header/body/expectation assertions use fallible parser setup"
)]
fn expect_head_and_body_share_original_framing() -> Result<(), Error> {
    use gnunet_rest::http::{Expectation, RequestHead};
    let limits = Limits::default();
    let prefix = b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n";
    let head = RequestHead::parse(prefix, limits)?;
    assert!(head.header_len() == prefix.len() && head.continue_expected());
    assert!(matches!(
        Request::parse(prefix, limits),
        Err(Error::Truncated)
    ));
    let full = b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n{}GET /copying HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let request = Request::parse(full, limits)?;
    assert!(request.body().contiguous() == Some(b"{}".as_slice()));
    assert!(request.consumed() == prefix.len() + 2);
    let mut head_path = [0; 2048];
    let mut full_path = [0; 2048];
    assert!(matches!(route::resolve_head(&head, &mut head_path)?,
        Resolution::Found(r) if r.endpoint() == Endpoint::IdentityCreate));
    assert!(matches!(route::resolve(&request, &mut full_path)?,
        Resolution::Found(r) if r.endpoint() == Endpoint::IdentityCreate));
    let duplicate = b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: , 100-CoNtInUe,\r\nExpect: 100-continue\r\n\r\n";
    let head = RequestHead::parse(duplicate, limits)?;
    assert!(head.expectation() == Expectation::Continue && head.continue_expected());
    for unsupported in [
        b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: extension\r\n\r\n".as_slice(),
        b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: 100-continue, extension\r\n\r\n".as_slice(),
    ] {
        assert!(RequestHead::parse(unsupported, limits)?.expectation() == Expectation::Unsupported);
        assert!(matches!(Request::parse(unsupported, limits), Err(Error::Unsupported)));
    }
    let ambiguous = b"POST /identity HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n";
    assert!(matches!(
        RequestHead::parse(ambiguous, limits),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        RequestHead::parse(
            prefix,
            Limits {
                body_bytes: 1,
                ..limits
            }
        ),
        Err(Error::TooLarge)
    ));
    let no_body = b"GET /copying HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n";
    assert!(!RequestHead::parse(no_body, limits)?.continue_expected());
    let old_version =
        b"POST /identity HTTP/1.0\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n{}";
    assert!(!RequestHead::parse(old_version, limits)?.continue_expected());
    assert!(Request::parse(old_version, limits)?.body().len() == 2);
    Ok(())
}
