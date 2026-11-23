use gnunet_gnsrecord::ZoneKey;
use gnunet_reclaim::{
    Identifier, Presentation, PresentationRequest,
    business::{Action, Completion, Job, Source},
};
use gnunet_types::Error;
use std::{
    fs::File,
    io::{self, Read},
};
use zeroize::Zeroizing;
/// Explicit native entropy owner plus linked Rust identity/credential functions.
/// Entropy is requested only for an admitted identifier operation. Construction
/// starts no work and consults no identity or private-key file.
pub struct SystemProviders {
    random: Entropy,
    failure: Option<SystemFailure>,
}
enum Entropy {
    Native,
    Device(File),
}
impl Entropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), SystemFailure> {
        match self {
            Self::Native => getrandom::fill(output).map_err(SystemFailure::NativeEntropy),
            Self::Device(file) => file.read_exact(output).map_err(SystemFailure::Entropy),
        }
    }
}
/// Actual local provider cause, without credential/key data.
#[derive(Debug)]
pub enum SystemFailure {
    /// Actual native kernel CSPRNG failure, without substituting another source.
    NativeEntropy(getrandom::Error),
    /// Actual read error from the explicitly supplied entropy device.
    Entropy(io::Error),
    /// Actual pinned helper format/availability failure, preserving raw kind/stage.
    Credential(gnunet_reclaim_credentials::Failure),
}
impl SystemProviders {
    /// Select the native kernel CSPRNG. No entropy request, service or worker
    /// starts here; each operation retains its actual platform failure.
    #[must_use]
    pub fn native() -> Self {
        Self {
            random: Entropy::Native,
            failure: None,
        }
    }
    /// Adopt an actual caller-owned OS entropy device for controlled platform
    /// provisioning. The caller is responsible for its CSPRNG provenance.
    #[must_use]
    pub fn from_random_device(random: File) -> Self {
        Self {
            random: Entropy::Device(random),
            failure: None,
        }
    }
    pub(crate) fn take_failure(&mut self) -> Option<SystemFailure> {
        self.failure.take()
    }
    pub(crate) fn run(&mut self, job: &mut Job, source: &Source, now: u64) -> Result<(), Error> {
        enum Done {
            Key(ZoneKey),
            Id(Zeroizing<[u8; 32]>),
            Presentation(Zeroizing<Vec<u8>>),
            Failed(Error),
        }
        // Direct functions execute synchronously under this exact original
        // prepared token. No observer runs and no await can replace the owner.
        let prepared = job.prepared()?.ok_or(Error::NotReady)?;
        let effect = prepared.effect.clone();
        let result = match prepared.action {
            Action::PublicKey { key } => {
                match gnunet_identity::SecretKey::from_serialized(key.expose_serialized())
                    .and_then(|private| private.public_key())
                    .and_then(|public| ZoneKey::from_wire(&public))
                {
                    Ok(public) => Done::Key(public),
                    Err(error) => Done::Failed(error),
                }
            }
            Action::Identifier => {
                let mut id = Zeroizing::new([0; 32]);
                match self.random.fill(&mut *id) {
                    Ok(()) => Done::Id(id),
                    Err(error) => {
                        self.failure = Some(error);
                        Done::Failed(Error::Entropy)
                    }
                }
            }
            Action::Presentation(request) => match present(request) {
                Ok(bytes) => Done::Presentation(bytes),
                Err(error) => {
                    let cause = error.cause;
                    self.failure = Some(SystemFailure::Credential(error));
                    Done::Failed(cause)
                }
            },
            _ => return Err(Error::Unsupported),
        };
        // The local function really ran. Record its original actual admission
        // and result; no fabricated native queued/written/ACK callback exists.
        job.admitted(&effect, source, now)?;
        match result {
            Done::Key(key) => job.complete(&effect, source, Completion::PublicKey(key), now),
            Done::Id(id) => job.complete(
                &effect,
                source,
                Completion::Identifier(Identifier::new(*id)),
                now,
            ),
            Done::Presentation(bytes) => job.complete(
                &effect,
                source,
                Completion::Presentation(Presentation::decode(&bytes)?),
                now,
            ),
            Done::Failed(error) => job.complete(&effect, source, Completion::Failed(error), now),
        }
    }
}
fn present(
    request: PresentationRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, gnunet_reclaim_credentials::Failure> {
    let credential = request.credential();
    let p = gnunet_reclaim_credentials::presentation(request)?;
    gnunet_reclaim_credentials::check_binding(p, credential)?;
    let local = |cause| gnunet_reclaim_credentials::Failure {
        family: gnunet_reclaim_credentials::Family::Credential,
        kind: credential.kind.value(),
        stage: gnunet_reclaim_credentials::Stage::Presentation,
        cause,
    };
    let len = p.encoded_len().map_err(local)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(len)
        .map_err(|_| local(Error::Capacity))?;
    bytes.resize(len, 0);
    p.encode(&mut bytes).map_err(local)?;
    Ok(bytes)
}
