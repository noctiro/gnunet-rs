//! Production grant publication, purpose27 signing/verification, PKCE and token
//! exchange with actual Unix consume clients. The signed grant/ticket and peer
//! replies are explicit fixtures, not native ticket-issuance or C interop facts.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Bounded actual handler and native-source regressions assert public result classifications"
)]
use super::*;
use crate::{
    ConsumeFailure, ConsumeProfile, OAuthChallenge,
    test_support::{Failure, MissingIdna, Reply, Setup, header, request},
};
use gnunet_identity::SecretKey;
use gnunet_rest::route::Endpoint;

const VERIFIER: &[u8] = b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &[u8] = b"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
fn provider(setup: &Setup, ttl: Duration) -> Result<Provider, Error> {
    Provider::new(
        setup.clock.clone(),
        Signer::Hs512(gnunet_oidc_crypto_host::Hs512::new(
            b"explicit nonsecret test signing key",
            Default::default(),
        )?),
        b"https://issuer.test",
        b"https://login.test/ui",
        None,
        Limits {
            ttl,
            ..Default::default()
        },
    )
}
fn key() -> Result<SecretKey, gnunet_types::Error> {
    let mut bytes = Zeroizing::new([31; 36]);
    bytes[..4].copy_from_slice(
        &gnunet_wire::official::identity::KeyType::Eddsa
            .value()
            .to_be_bytes(),
    );
    SecretKey::from_serialized(&bytes[..])
}
async fn issue(
    context: &Context<'_, MissingIdna>,
    provider: &Provider,
    key: &SecretKey,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let subject = ZoneKey::from_wire(&key.public_key()?)?;
    let client = public_text(subject)?;
    let mut ticket_text = Zeroizing::new(Vec::new());
    ticket_text.extend_from_slice(b"FIXTURE.");
    ticket_text.extend_from_slice(&client);
    let code = oidc::Code {
        ticket: gnunet_reclaim::Ticket::new(&ticket_text)?,
        nonce: b"fixture-nonce",
        challenge: CHALLENGE,
        attributes: AttributeList::empty(),
        presentations: PresentationList::empty(),
    };
    let mut raw = bytes(code.encoded_len(provider.limits.code)?)?;
    let n = code.sign(
        key.view()?,
        &mut bytes(provider.limits.code.bytes)?,
        &mut raw,
        provider.limits.code,
    )?;
    raw.truncate(n);
    let mut encoded = bytes(base64::encoded_len(n, false)?)?;
    base64::encode(&raw, &mut encoded, true, false)?;
    let until = provider
        .now()?
        .checked_add(2_000_000)
        .ok_or(Fault::Overflow)?;
    let reservation = provider.reserve()?;
    reservation
        .publish(
            copy(&encoded)?,
            copy(&client)?,
            copy(b"https://rp.test/cb")?,
            subject,
            until,
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
    drop(reservation);
    let mut form = Zeroizing::new(Vec::new());
    form.extend_from_slice(b"grant_type=authorization_code&code=");
    form.extend_from_slice(&encoded);
    form.extend_from_slice(b"&client_id=");
    form.extend_from_slice(&client);
    form.extend_from_slice(b"&redirect_uri=https%3A%2F%2Frp.test%2Fcb&code_verifier=");
    form.extend_from_slice(VERIFIER);
    let response = context
        .execute(request("POST", "/openid/token", &form, None)?)
        .await?;
    if response.status != 200 {
        return Err("token fixture exchange failed".into());
    }
    parse(&response.body, Default::default(), |root| {
        decoded(
            root.get(b"access_token")
                .ok_or(Fault::Malformed)?
                .string()?,
        )
    })
    .map_err(Into::into)
}
fn bearer(token: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut value = Zeroizing::new(Vec::new());
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(token);
    value
}

#[test]
fn userinfo_denial_is_bearer_401_but_provider_failure_unknown_loss_and_timeout_are_independent()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for (profile, success, failed) in [
                (ConsumeProfile::Canonical, 1, u32::MAX),
                (ConsumeProfile::CNativeLittle, 0x0001_0000, 0xffff_0000),
            ] {
                let setup = Setup::new()?;
                let key = key()?;
                let subject = ZoneKey::from_wire(&key.public_key()?)?;
                let peer = setup.peer(
                    subject,
                    vec![
                        Reply::Status(0),
                        Reply::Status(failed),
                        Reply::Status(2),
                        Reply::Disconnect,
                        Reply::NoResponse,
                        Reply::Status(success),
                    ],
                )?;
                let outcome: Result<(), Failure> = async {
                    let provider = provider(&setup, Duration::from_secs(10))?;
                    let context = setup
                        .context(profile, Duration::from_millis(100))?
                        .with_oidc(&provider)?;
                    // Local grant verification/signing is setup for the consume
                    // cases; its deadline must not be the no-response probe's.
                    let issuance = setup
                        .context(profile, Duration::from_secs(2))?
                        .with_oidc(&provider)?;
                    let token = issue(&issuance, &provider, &key).await?;
                    let bearer = bearer(&token);
                    for index in 0..6 {
                        let result = context
                            .execute(request("GET", "/openid/userinfo", &[], Some(&bearer))?)
                            .await;
                        let response = match result {
                            Ok(response) if index == 5 => response,
                            Err(error) if index != 5 => {
                                match (&error, index) {
                                    (
                                        Error::OAuth {
                                            status: 401,
                                            challenge: Some(OAuthChallenge::ResourceBearer),
                                            service_status: Some(0),
                                            ..
                                        },
                                        0,
                                    )
                                    | (
                                        Error::Consume {
                                            cause: ConsumeFailure::Service,
                                            ..
                                        },
                                        1,
                                    )
                                    | (
                                        Error::Consume {
                                            cause: ConsumeFailure::Unknown,
                                            ..
                                        },
                                        2,
                                    )
                                    | (Error::ReclaimSource(_), 3)
                                    | (Error::Deadline, 4) => {}
                                    _ => {
                                        return Err(format!(
                                            "userinfo case {index} returned {error}"
                                        )
                                        .into());
                                    }
                                }
                                crate::http::error_response(&error, Some(Endpoint::Userinfo), 4096)?
                            }
                            Ok(response) => {
                                return Err(format!(
                                    "userinfo case {index} unexpectedly returned HTTP {}",
                                    response.status
                                )
                                .into());
                            }
                            Err(error) => {
                                return Err(
                                    format!("userinfo case {index} returned {error}").into()
                                );
                            }
                        };
                        assert_eq!(response.status, [401, 502, 502, 502, 504, 200][index]);
                        assert_eq!(
                            response.service_status,
                            [
                                Some(0),
                                Some(i64::from(failed)),
                                Some(2),
                                None,
                                None,
                                Some(i64::from(success))
                            ][index]
                        );
                        assert_eq!(
                            header(&response, b"WWW-Authenticate"),
                            if index == 0 {
                                Some(b"Bearer".as_slice())
                            } else {
                                None
                            }
                        );
                        assert_eq!(
                            header(&response, b"Cache-Control"),
                            Some(b"no-store".as_slice())
                        );
                        // No failure reissues, renews or speculatively removes the
                        // original access owner. Every iteration reached the real MQ.
                        assert_eq!(provider.state.borrow().accesses.iter().flatten().count(), 1);
                    }
                    Ok(())
                }
                .await;
                peer.finish(outcome)?;
            }
            Ok(())
        })
}

#[test]
fn token_client_authentication_and_expired_bearer_challenges_are_flow_specific()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let setup = Setup::new()?;
            let provider = provider(&setup, Duration::from_secs(1))?;
            let context = setup
                .context(ConsumeProfile::Canonical, Duration::from_secs(2))?
                .with_oidc(&provider)?;
            for authorization in [
                b"Basic !!!".as_slice(),
                b"Basic bm90LWEta2V5OnNlY3JldA==".as_slice(),
            ] {
                // The second header is valid Basic(not-a-key:secret). It must reach
                // the token owner's client-id validation, not fail Base64 parsing.
                let error = context
                    .execute(request(
                        "POST",
                        "/openid/token",
                        b"grant_type=authorization_code&code=unused",
                        Some(authorization),
                    )?)
                    .await
                    .err()
                    .ok_or("invalid client accepted")?;
                assert!(matches!(
                    &error,
                    Error::OAuth {
                        status: 401,
                        challenge: Some(OAuthChallenge::ClientBasic),
                        ..
                    }
                ));
                let response = crate::http::error_response(&error, Some(Endpoint::Token), 4096)?;
                assert_eq!(
                    header(&response, b"WWW-Authenticate"),
                    Some(b"Basic".as_slice())
                );
                assert_eq!(response.service_status, None);
                assert!(
                    header(
                        &crate::http::error_response(&error, Some(Endpoint::Names), 4096)?,
                        b"WWW-Authenticate"
                    )
                    .is_none()
                );
            }
            let key = key()?;
            let token = issue(&context, &provider, &key).await?;
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let error = context
                .execute(request(
                    "GET",
                    "/openid/userinfo",
                    &[],
                    Some(&bearer(&token)),
                )?)
                .await
                .err()
                .ok_or("expired token accepted")?;
            assert!(matches!(
                &error,
                Error::OAuth {
                    status: 401,
                    error: "invalid_token",
                    challenge: Some(OAuthChallenge::ResourceBearer),
                    service_status: None,
                    ..
                }
            ));
            let response = crate::http::error_response(&error, Some(Endpoint::Userinfo), 4096)?;
            assert_eq!(
                header(&response, b"WWW-Authenticate"),
                Some(b"Bearer".as_slice())
            );
            assert!(
                header(
                    &crate::http::error_response(&error, Some(Endpoint::Token), 4096)?,
                    b"WWW-Authenticate"
                )
                .is_none()
            );
            Ok(())
        })
}
