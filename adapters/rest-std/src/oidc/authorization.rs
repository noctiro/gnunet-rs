//! Authorization code inputs that must be valid before ticket issuance.
use super::{Error, Fault, OwnedRequest, Zeroizing, oauth, oidc};

pub(super) struct CodeInputs {
    pub(super) nonce: Zeroizing<Vec<u8>>,
    pub(super) challenge: Zeroizing<Vec<u8>>,
}

impl CodeInputs {
    pub(super) fn parse(
        request: &OwnedRequest,
        cap: usize,
        nonce_limit: usize,
    ) -> Result<Self, Error> {
        let read = |name: &[u8]| {
            request.parameter(name, cap).map_err(|error| match error {
                Error::Core(Fault::Conflict | Fault::Malformed | Fault::Truncated) => {
                    oauth(400, "invalid_request", "Invalid nonce or S256 parameter")
                }
                error => error,
            })
        };
        let nonce = read(b"nonce")?.unwrap_or_default();
        let challenge = read(b"code_challenge")?;
        let method = read(b"code_challenge_method")?;
        validate_authorization_code_inputs(
            &nonce,
            challenge.as_deref().map(Vec::as_slice),
            method.as_deref().map(Vec::as_slice),
            nonce_limit,
        )?;
        Ok(Self {
            nonce,
            challenge: challenge.unwrap_or_default(),
        })
    }
}

fn validate_authorization_code_inputs(
    nonce: &[u8],
    challenge: Option<&[u8]>,
    method: Option<&[u8]>,
    nonce_limit: usize,
) -> Result<(), Error> {
    match (challenge, method) {
        (None, None) | (Some([_, ..]), Some(b"S256")) => {}
        (None | Some([]), _) => {
            return Err(oauth(400, "invalid_request", "Missing code challenge"));
        }
        (Some(_), _) => {
            return Err(oauth(
                400,
                "invalid_request",
                "Only S256 code challenges are supported",
            ));
        }
    }
    oidc::validate_code_inputs(nonce, challenge.unwrap_or_default(), nonce_limit)
        .map_err(|_| oauth(400, "invalid_request", "Invalid nonce or S256 challenge"))
}

#[cfg(test)]
mod tests {
    use super::super::trusted_authorization_error;
    use super::{CodeInputs, Error, validate_authorization_code_inputs};
    use crate::test_support::{Failure, header, request};

    #[test]
    fn authorization_code_inputs_are_validated_before_ticket_issuance() {
        let challenge = b"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".as_slice();
        let s256 = Some(b"S256".as_slice());
        assert!(validate_authorization_code_inputs(b"nonce", Some(challenge), s256, 5).is_ok());
        assert!(validate_authorization_code_inputs(b"", None, None, 5).is_ok());

        for (nonce, challenge, method) in [
            (b"too-long".as_slice(), Some(challenge), s256),
            (b"nul\0", None, None),
            (b"\xff", None, None),
            (b"nonce", None, s256),
            (b"nonce", Some(b""), None),
            (b"nonce", Some(challenge), None),
            (b"nonce", Some(challenge), Some(b"plain")),
            (b"nonce", Some(&challenge[..42]), s256),
            (
                b"nonce",
                Some(b"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"),
                s256,
            ),
        ] {
            assert!(matches!(
                validate_authorization_code_inputs(nonce, challenge, method, 5),
                Err(Error::OAuth {
                    status: 400,
                    error: "invalid_request",
                    ..
                })
            ));
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure authorization regression asserts the response contract after callback validation"
    )]
    fn malformed_or_ambiguous_fields_keep_the_trusted_callback_and_state() -> Result<(), Failure> {
        for target in [
            "/openid/authorize?nonce=%FF",
            "/openid/authorize?nonce=a&nonce=b",
        ] {
            let request = request("GET", target, &[], None)?;
            let Err(error) = CodeInputs::parse(&request, 1024, 16) else {
                return Err("invalid authorization code inputs were accepted".into());
            };
            let response = trusted_authorization_error(error, b"https://rp.test/cb", b"a/b", 1024)?;
            let location = header(&response, b"Location").ok_or("missing trusted callback")?;
            assert_eq!(response.status, 302);
            assert!(location.starts_with(b"https://rp.test/cb?error=invalid_request&"));
            assert!(location.ends_with(b"&state=a%2Fb"));
        }
        Ok(())
    }
}
