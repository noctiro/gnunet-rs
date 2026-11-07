//! Deliberate public CLI output; no private zone or complete native frame enters JSON.
use super::*;
fn value(bytes: &[u8]) -> Value {
    json!({"text":String::from_utf8_lossy(bytes),"hex":hexadecimal(bytes)})
}
fn attribute(a: Attribute<'_>) -> Value {
    json!({"id_hex":hexadecimal(a.id.bytes()),"credential_id_hex":hexadecimal(a.credential.bytes()),
    "type":a.kind.value(),"flags":a.flags,"name":value(a.name.wire_bytes()),"value":value(a.value.expose())})
}
fn credential(c: Credential<'_>) -> Value {
    json!({"id_hex":hexadecimal(c.id.bytes()),"type":c.kind.value(),"flags":c.flags,
    "name":value(c.name.wire_bytes()),"value":value(c.value.expose()),"authenticity":"unverified"})
}
fn presentation(p: Presentation<'_>) -> Value {
    json!({"credential_id_hex":hexadecimal(p.credential.bytes()),"type":p.kind.value(),
    "value":value(p.value.expose()),"authenticity":"unverified"})
}
/// Print actual raw fields and return only the ordinary public success semantics.
pub(super) fn reply<W: Write>(
    out: &mut Output<'_, W>,
    response: ipc::Response<'_>,
) -> Result<bool> {
    let (row, success) = match response {
        ipc::Response::Success { rid, result } => (
            json!({"event":"reclaim_result","rid":rid,"result":result,"actual_service_reply":true}),
            result == 1,
        ),
        ipc::Response::Revoked { rid, result } => (
            json!({"event":"reclaim_revoked","rid":rid,"result":result,"actual_service_reply":true,"cached_ticket_revocation_immediate":false}),
            result == 1,
        ),
        ipc::Response::Attribute {
            rid,
            identity,
            attribute: a,
            ..
        } => (
            json!({"event":"reclaim_attribute","rid":rid,
            "service_public_identity_hex":identity.map(|p|hexadecimal(&p.to_wire())),"attribute":a.map(attribute)}),
            true,
        ),
        ipc::Response::Credential {
            rid,
            identity,
            credential: c,
        } => (
            json!({"event":"reclaim_credential","rid":rid,
            "service_public_identity_hex":identity.map(|p|hexadecimal(&p.to_wire())),"credential":c.map(credential)}),
            true,
        ),
        ipc::Response::Ticket {
            rid,
            ticket,
            uri,
            presentations,
        } => {
            let mut p = Vec::new();
            p.try_reserve_exact(presentations.len())?;
            for v in presentations.iter() {
                p.push(presentation(v));
            }
            (
                json!({"event":"reclaim_ticket","rid":rid,"ticket":ticket.map(|v|value(v.expose())),
                "rp_uri":uri.map(|v|value(v.expose())),"presentations":p,"authenticity":"unverified"}),
                ticket.is_some(),
            )
        }
        ipc::Response::Consumed {
            rid,
            result,
            identity,
            attributes,
            presentations,
            ..
        } => {
            let mut a = Vec::new();
            a.try_reserve_exact(attributes.len())?;
            for v in attributes.iter() {
                a.push(attribute(v));
            }
            let mut p = Vec::new();
            p.try_reserve_exact(presentations.len())?;
            for v in presentations.iter() {
                p.push(presentation(v));
            }
            (
                json!({"event":"reclaim_consumed","rid":rid,"raw_result":result,"ordinary_success_word":result==1,
                "c_producer_status_defect_not_normalized":true,"service_public_identity_hex":identity.map(|p|hexadecimal(&p.to_wire())),
                "attributes":a,"presentations":p,"credential_authenticity":"unverified"}),
                result == 1,
            )
        }
    };
    out.emit(row)?;
    Ok(success)
}
pub(super) fn is_end(response: ipc::Response<'_>, kind: ipc::Iteration) -> bool {
    matches!(
        (kind, response),
        (
            ipc::Iteration::Attributes,
            ipc::Response::Attribute {
                identity: None,
                attribute: None,
                ..
            },
        ) | (
            ipc::Iteration::Credentials,
            ipc::Response::Credential {
                identity: None,
                credential: None,
                ..
            },
        ) | (
            ipc::Iteration::Tickets,
            ipc::Response::Ticket { ticket: None, .. }
        )
    )
}
pub(super) fn object_id(response: ipc::Response<'_>) -> Option<Identifier> {
    match response {
        ipc::Response::Attribute {
            attribute: Some(v), ..
        } => Some(v.id),
        ipc::Response::Credential {
            credential: Some(v),
            ..
        } => Some(v.id),
        _ => None,
    }
}
pub(super) fn object_name<'a>(response: ipc::Response<'a>) -> Option<&'a [u8]> {
    match response {
        ipc::Response::Attribute {
            attribute: Some(v), ..
        } => Some(v.name.bytes()),
        ipc::Response::Credential {
            credential: Some(v),
            ..
        } => Some(v.name.bytes()),
        _ => None,
    }
}
pub(super) fn object(response: ipc::Response<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let length = match response {
        ipc::Response::Attribute {
            attribute: Some(a), ..
        } => a.encoded_len()?,
        ipc::Response::Credential {
            credential: Some(c),
            ..
        } => c.encoded_len()?,
        _ => return Err("expected one original object".into()),
    };
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    match response {
        ipc::Response::Attribute {
            attribute: Some(a), ..
        } => {
            a.encode(&mut bytes)?;
        }
        ipc::Response::Credential {
            credential: Some(c),
            ..
        } => {
            c.encode(&mut bytes)?;
        }
        _ => return Err("expected original object".into()),
    };
    Ok(bytes)
}
pub(super) fn observe<W: Write>(out: &mut Output<'_, W>, progress: &Progress<'_>) -> Result<()> {
    let row = match progress {
        Progress::Connected(epoch) => {
            json!({"event":"reclaim_connected","epoch":epoch.diagnostic()})
        }
        Progress::Queued {
            epoch,
            operation,
            request_id,
        } => {
            json!({"event":"reclaim_queued","epoch":epoch.diagnostic(),"operation":operation.diagnostic(),"rid":request_id,"service_result":false})
        }
        Progress::Written {
            epoch,
            operation,
            request_id,
        } => {
            json!({"event":"reclaim_whole_write","epoch":epoch.diagnostic(),"operation":operation.diagnostic(),"rid":request_id,"service_result":false})
        }
        Progress::ControlQueued {
            epoch,
            control,
            kind,
        } => {
            json!({"event":"reclaim_control_queued","epoch":epoch.diagnostic(),"control":control.diagnostic(),"kind":format!("{kind:?}")})
        }
        Progress::ControlWritten {
            epoch,
            control,
            kind,
        } => {
            json!({"event":"reclaim_control_whole_write","epoch":epoch.diagnostic(),"control":control.diagnostic(),"kind":format!("{kind:?}"),"service_ack":false})
        }
        Progress::Lost { report, cause } => {
            json!({"event":"reclaim_source_lost","epoch":report.epoch.map(|e|e.diagnostic()),"operations":report.operations,"exposed":report.exposed,"cause":format!("{cause:?}")})
        }
        Progress::ConnectRetry { error, retry_after } => {
            json!({"event":"reclaim_connect_retry","error":error.to_string(),"retry_after_ms":retry_after.as_millis()})
        }
        Progress::Ignored { epoch, request_id } => {
            json!({"event":"reclaim_late_ignored","epoch":epoch.diagnostic(),"rid":request_id})
        }
        _ => return Ok(()),
    };
    out.emit(row)
}
pub(super) fn loss<W: Write>(
    out: &mut Output<'_, W>,
    report: Option<native::Loss<'_>>,
) -> Result<()> {
    if let Some(r) = report {
        out.emit(json!({"event":"reclaim_source_closed","epoch":r.epoch.map(|e|e.diagnostic()),
        "operations":r.operations,"exposed":r.exposed,"control":r.control.map(|c|json!({"control":c.control.diagnostic(),"kind":format!("{:?}",c.kind),"submission":format!("{:?}",c.submission)})),"remote_quiescence":false}))?;
    }
    Ok(())
}
