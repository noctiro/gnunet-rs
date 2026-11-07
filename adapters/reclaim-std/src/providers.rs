use gnunet_gnsrecord::ZoneKey;
use gnunet_reclaim::{
    AttributeList, Credential, Identifier, Presentation,
    business::{Action, Completion, Job, Source},
};
use gnunet_types::Error;
use std::{
    fs::File,
    io::{self, Read},
};
use zeroize::Zeroizing;
/// Explicit OS entropy owner plus linked Rust identity/credential functions.
/// Opening it happens only when the foreground caller requests it, after UID
/// setup. It opens /dev/urandom only; no identity/private key file is consulted.
pub struct SystemProviders {
    random: File,
    failure: Option<SystemFailure>,
}
/// Actual local provider cause, without credential/key data.
#[derive(Debug)]
pub enum SystemFailure {
    /// Actual kernel entropy read error.
    Entropy(io::Error),
    /// Actual pinned helper format/availability failure, preserving raw kind/stage.
    Credential(gnunet_reclaim_credentials::Failure),
}
impl SystemProviders {
    /// Open the actual kernel CSPRNG source. No service/worker/thread is started.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            random: File::open("/dev/urandom")?,
            failure: None,
        })
    }
    /// Adopt an actual caller-owned OS entropy device for controlled platform
    /// provisioning. The caller is responsible for its CSPRNG provenance.
    #[must_use]
    pub fn from_random_device(random: File) -> Self {
        Self {
            random,
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
                match self.random.read_exact(&mut *id) {
                    Ok(()) => Done::Id(id),
                    Err(error) => {
                        self.failure = Some(SystemFailure::Entropy(error));
                        Done::Failed(Error::Entropy)
                    }
                }
            }
            Action::Presentation {
                credential,
                selected,
            } => match present(credential, selected) {
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
    credential: Credential<'_>,
    selected: AttributeList<'_>,
) -> Result<Zeroizing<Vec<u8>>, gnunet_reclaim_credentials::Failure> {
    let p = gnunet_reclaim_credentials::presentation(credential, selected)?;
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
