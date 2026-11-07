//! Native FS admin transitions over original owners.
use super::*;
impl<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter>
    Server<'id, 'slots, 'seen, S, L, R>
{
    pub(super) fn poll_admin(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        let Some(mut admin) = self.admin.take() else {
            return Poll::Pending;
        };
        if let Some(job) = &mut admin.pending {
            match job.poll(cx) {
                Poll::Pending => {
                    self.admin = Some(admin);
                    return Poll::Pending;
                }
                Poll::Ready(output) => {
                    admin.pending = None;
                    admin.output = Some(output);
                }
            }
        }
        if self.peer(admin.client).is_none() {
            if let Some(Err(error)) = admin.output {
                self.fault(Some(admin.client.value()), error, observe);
            }
            return Poll::Ready(());
        }
        if !self.ready(admin.client) {
            self.admin = Some(admin);
            return Poll::Pending;
        }
        if let Some(output) = admin.output.take() {
            let result = match output {
                Err(error) => {
                    if matches!(admin.kind, AdminKind::Register) && !error.fatal() {
                        let message = match error.as_ref() {
                            Error::Index(e) => e.message(),
                            _ => b"index registration refused",
                        };
                        self.fault(Some(admin.client.value()), error, observe);
                        encode(Response::IndexFailed { message })
                            .and_then(|frame| self.queue(admin.client, frame))
                            .map(|()| false)
                    } else {
                        Err(error)
                    }
                }
                Ok(Output::Registered) => encode(Response::IndexStarted)
                    .and_then(|f| self.queue(admin.client, f))
                    .map(|()| false),
                Ok(Output::Removed) => encode(Response::Unindexed)
                    .and_then(|f| self.queue(admin.client, f))
                    .map(|()| false),
                Ok(Output::Entry { file_id, frame }) => {
                    admin.after = Some(file_id);
                    self.queue(admin.client, frame).map(|()| true)
                }
                Ok(Output::End(frame)) => self.queue(admin.client, frame).map(|()| false),
                Ok(Output::Resolved(_) | Output::Maintained) => {
                    Err(Arc::new(Error::Protocol(ProtocolError::Malformed)))
                }
            };
            match result {
                Ok(true) => self.admin = Some(admin),
                Ok(false) => {
                    if let Some(i) = self.peer(admin.client)
                        && let Some(p) = &mut self.peers[i]
                    {
                        p.control = false;
                    }
                }
                Err(error) => {
                    self.fault(Some(admin.client.value()), error, observe);
                    self.close_client(admin.client, observe);
                }
            }
            return Poll::Ready(());
        }
        match self.worker.submit(Task::Next(admin.after)) {
            Ok(job) => {
                admin.pending = Some(job);
                self.admin = Some(admin);
                cx.waker().wake_by_ref();
            }
            Err(error) => {
                self.fault(Some(admin.client.value()), error, observe);
                self.close_client(admin.client, observe);
            }
        }
        Poll::Ready(())
    }
    pub(super) fn poll_sign(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        let Some(client) = self.sign_client else {
            return Poll::Pending;
        };
        if self.signed.is_none() {
            match self.signer.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(SignProgress::Activity)) => return Poll::Ready(()),
                Poll::Ready(Ok(SignProgress::Signed(value))) => self.signed = Some(value),
                Poll::Ready(Err(e)) => {
                    self.sign_client = None;
                    self.fault(Some(client.value()), Arc::new(Error::Port(e)), observe);
                    self.close_client(client, observe);
                    return Poll::Ready(());
                }
            }
        }
        if self.peer(client).is_none() {
            self.sign_client = None;
            self.signed = None;
            return Poll::Ready(());
        }
        if !self.ready(client) {
            return Poll::Pending;
        }
        let Some(location) = self.signed.take() else {
            return Poll::Pending;
        };
        self.sign_client = None;
        let result = encode(Response::LocSignature {
            expiration: location.expiration(),
            signature: *location.signature().as_bytes(),
            peer: *location.peer().as_bytes(),
        })
        .and_then(|f| self.queue(client, f));
        match result {
            Ok(()) => {
                if let Some(i) = self.peer(client)
                    && let Some(p) = &mut self.peers[i]
                {
                    p.control = false;
                }
            }
            Err(error) => {
                self.fault(Some(client.value()), error, observe);
                self.close_client(client, observe);
            }
        }
        Poll::Ready(())
    }
}
