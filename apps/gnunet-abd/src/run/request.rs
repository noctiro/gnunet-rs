use super::{Control, SharedFacts};
use crate::{
    Failure,
    output::Buffer,
    text::{Buffers, bytes},
};
use gnunet_abd::{Credential, Principal};
use gnunet_abd_client_host::{self as abd, ipc};
use zeroize::Zeroizing;

struct Original {
    client: abd::Client,
    facts: SharedFacts,
    closed: bool,
}
impl Original {
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut facts = self.facts.borrow_mut();
        facts.abd_receipt = Some(self.client.receipt());
        if let Some(loss) = self.client.close() {
            facts.abd_loss.get_or_insert(loss);
        }
    }
}
impl Drop for Original {
    fn drop(&mut self) {
        self.close();
    }
}

/// Each signed leaf is checked intact before its official plural encoding.
/// Subject roles are explicitly unsupported by that transport, not discarded.
async fn leaves(
    control: &mut Control,
    input: &[u8],
    buffers: &mut Buffers,
) -> Result<(Zeroizing<Vec<u8>>, u32), Failure> {
    let text = std::str::from_utf8(input)?;
    if text.trim().is_empty() {
        return Ok((bytes(0)?, 0));
    }
    let mut encoded = bytes(0)?;
    let mut count = 0u32;
    for item in text.split(',') {
        control.gate().await?;
        let item = item.trim();
        if item.is_empty() {
            return Err("empty signed DEL between comma separators".into());
        }
        count = count.checked_add(1).ok_or(gnunet_types::Error::Overflow)?;
        if usize::try_from(count)? > control.settings.records {
            return Err("too many signed DEL leaves".into());
        }
        let canonical = buffers.parse(gnunet_gnsrecord::RecordType::DELEGATE, item.as_bytes())?;
        let credential = Credential::verify_record(
            &canonical,
            control.time()?,
            control.settings.name_bytes,
            control.settings.text_bytes,
        )?;
        let delegate = credential.view()?.delegate();
        if delegate.subject_attribute.is_some() {
            return Err("official plural ABD IPC cannot preserve a signed subject role; this DEL is not submitted".into());
        }
        let n = delegate.ipc_len(false)?;
        let start = encoded.len();
        let end = start.checked_add(n).ok_or(gnunet_types::Error::Overflow)?;
        if end > control.settings.abd.frame_bytes {
            return Err("signed DEL leaves exceed one official ABD request frame".into());
        }
        encoded.try_reserve_exact(n)?;
        if encoded.capacity() > control.settings.abd.frame_bytes {
            return Err("signed DEL allocation exceeds the frame bound".into());
        }
        encoded.resize(end, 0);
        delegate.encode_ipc(&mut encoded[start..], false)?;
    }
    Ok((encoded, count))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the original public request scope and shared deadline are independent inputs"
)]
pub(super) async fn verify(
    control: &mut Control,
    source: abd::EndpointSource,
    subject: Principal,
    issuer: Principal,
    attribute: &[u8],
    input: &[u8],
    direction: u16,
    buffers: &mut Buffers,
) -> Result<(), Failure> {
    let (encoded, count) = leaves(control, input, buffers).await?;
    control.gate().await?;
    let request = ipc::Request::Verify {
        id: 1,
        subject: subject.view()?,
        issuer: issuer.view()?,
        attribute,
        resolution: direction,
        delegates: ipc::Delegates::new(&encoded, count)?,
    };
    let client = abd::Client::new(source, &request, control.settings.abd, control.original)?;
    drop(encoded);
    drive(control, client, buffers).await
}

pub(super) async fn collect(
    control: &mut Control,
    source: abd::EndpointSource,
    secret: gnunet_identity::SecretKey,
    issuer: Principal,
    attribute: &[u8],
    direction: u16,
    buffers: &mut Buffers,
) -> Result<(), Failure> {
    control.gate().await?;
    // This secret is borrowed solely by the immutable original request encoder.
    // The native owner erases its frame; no key is logged or put in argv.
    let request = ipc::Request::Collect {
        id: 1,
        subject: ipc::PrivateKey::new(secret.expose_serialized())?,
        issuer: issuer.view()?,
        attribute,
        resolution: direction,
    };
    let client = abd::Client::new(source, &request, control.settings.abd, control.original)?;
    drop(secret);
    drive(control, client, buffers).await
}

async fn terminal(
    control: &mut Control,
    buffers: &mut Buffers,
    observation: &abd::Observation,
) -> Result<(), Failure> {
    let ipc::Response::Result {
        found,
        chain,
        delegates,
        ..
    } = observation.view()?
    else {
        return Err("ABD terminal event was not an original terminal result".into());
    };
    control.facts.borrow_mut().found = Some(found);
    if found != 0 && found != 1 {
        return Err(format!("ABD returned unsupported raw del_found={found}").into());
    }
    let mut output = Buffer::new(control.settings.output_bytes);
    if found == 0 {
        output.append(b"No delegation found.\n")?;
        crate::output::write(control, output.bytes()).await?;
        return Err(
            "ABD actual terminal response did not establish the requested delegation".into(),
        );
    }
    output.append(b"Delegation found.\nchain-edges: ")?;
    output.number(chain.count())?;
    output.append(b"\nsigned-leaves: ")?;
    output.number(delegates.count())?;
    output.append(b"\n")?;
    // These edges are source-reported unsigned data, distinct from the
    // authenticated purpose28 leaves rendered only after verification below.
    for edge in chain.iter() {
        control.gate().await?;
        output.append(b"edge ")?;
        output.key(edge.issuer)?;
        output.append(b" ")?;
        output.escaped(edge.issuer_attribute)?;
        output.append(b" -> ")?;
        output.key(edge.subject)?;
        if let Some(role) = edge.subject_attribute {
            output.append(b" ")?;
            output.escaped(role)?;
        }
        output.append(b"\n")?;
    }
    for delegate in delegates.iter() {
        control.gate().await?;
        let credential = Credential::verify_ipc(
            delegate,
            control.time()?,
            control.settings.name_bytes,
            control.settings.text_bytes,
        )?;
        let text = buffers.format(gnunet_gnsrecord::RecordType::DELEGATE, credential.bytes())?;
        crate::output::record_line(&text)?;
        output.append(b"DEL ")?;
        output.append(&text)?;
        output.append(b"\n")?;
    }
    crate::output::write(control, output.bytes()).await
}

async fn drive(
    control: &mut Control,
    client: abd::Client,
    buffers: &mut Buffers,
) -> Result<(), Failure> {
    let mut original = Original {
        client,
        facts: control.facts.clone(),
        closed: false,
    };
    loop {
        let event = control.next(|cx| original.client.poll_progress(cx)).await?;
        match event {
            abd::Progress::Written { receipt, .. }
            | abd::Progress::Intermediate { receipt, .. } => {
                control.facts.borrow_mut().abd_receipt = Some(receipt);
            }
            abd::Progress::Result {
                observation,
                receipt,
            } => {
                // The actual native client checked original kind/RID and whole
                // write, then physically closed this exact original source.
                control.facts.borrow_mut().abd_receipt = Some(receipt);
                return terminal(control, buffers, &observation).await;
            }
            abd::Progress::Lost(loss) => {
                control.facts.borrow_mut().abd_receipt = Some(loss.receipt.clone());
                control.facts.borrow_mut().abd_loss.get_or_insert(loss);
                return Err(
                    "original ABD source ended before its terminal result; no replay".into(),
                );
            }
            abd::Progress::Retry(error) => {
                control.facts.borrow_mut().abd_retry.get_or_insert(error);
            }
            abd::Progress::Attached(_) | abd::Progress::Activity { .. } => {}
        }
    }
}
