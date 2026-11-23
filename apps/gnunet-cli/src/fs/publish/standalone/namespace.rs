//! Configured Identity authority for root SKS publication.
use super::{Gate, Result};
use gnunet::{
    clients::identity::{
        Instance, KeyType, Limits, Lookup, LookupOutcome, LookupProgress, Progress, SecretKey, ipc,
    },
    crypto::{EddsaPublicKey, gns::EdkeySecret},
    datastore_host::{Instance as StoreInstance, ReservationSlot, Slot},
    fs::{Limits as UriLimits, Namespace, Uri, metadata},
    fs_host::{
        Buffers, Control,
        extraction::Policy,
        ipc::EndpointSource,
        namespace::graph::{Graph, Limits as GraphLimits},
        network::ublock::UblockOptions,
    },
};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};
use zeroize::Zeroizing;

pub(in crate::fs::publish) struct Selection {
    name: Vec<u8>,
    label: Vec<u8>,
    update: Option<Vec<u8>>,
}

impl Selection {
    pub(super) fn new(
        name: Option<Vec<u8>>,
        label: Option<Vec<u8>>,
        update: Option<Vec<u8>>,
    ) -> Result<Option<Self>> {
        let selected = match (name, label, update) {
            (None, None, None) => return Ok(None),
            (None, _, _) => return Err("gnunet-publish -t and -N require -P".into()),
            (_, None, _) => return Err("gnunet-publish -P requires -t".into()),
            (Some(name), Some(label), update) => Self {
                name,
                label,
                update,
            },
        };
        let limit = gnunet::fs::ublock::Limits::default().max_label_bytes;
        ipc::Request::Lookup {
            name: &selected.name,
        }
        .encoded_len()?;
        if selected.name.is_empty()
            || selected.label.len() > limit
            || selected.label.contains(&0)
            || selected
                .update
                .as_ref()
                .is_some_and(|value| value.len() > limit || value.contains(&0))
        {
            return Err("invalid or excessive publication namespace argument".into());
        }
        Ok(Some(selected))
    }

    pub(super) fn graph_root(
        &self,
        config: &gnunet_config::Configuration,
    ) -> Result<Option<PathBuf>> {
        if self.update.is_none() {
            return Ok(None);
        }
        let dir = if config.get(b"fs", b"UPDATE_DIR").is_some() {
            config.get_path("fs", "UPDATE_DIR")?
        } else {
            config
                .get_path("paths", "GNUNET_DATA_HOME")?
                .join("fs")
                .join("updates")
        };
        Ok(Some(dir.join("rust")))
    }

    pub(super) async fn lookup(
        &self,
        source: EndpointSource,
        until: u64,
        gate: &mut Gate,
    ) -> Result<SecretKey> {
        let instance = Instance::new();
        let mut lookup = Lookup::exact(&instance, source, &self.name, until, Limits::default())?;
        let hard = gate.hard;
        let result = loop {
            let next = lookup.drive(Some(hard.into()));
            let mut next = std::pin::pin!(next);
            let result = poll_fn(|cx| {
                gate.poll(cx);
                if gate.stop.load(Ordering::Acquire) {
                    return std::task::Poll::Ready(Ok(None));
                }
                next.as_mut().poll(cx).map(|result| result.map(Some))
            })
            .await;
            match result {
                Ok(Some(LookupProgress::Finished {
                    outcome: LookupOutcome::Found(identity),
                    ..
                })) if identity.name() == self.name.as_slice() => break Ok(identity.into_secret()),
                Ok(Some(LookupProgress::Finished {
                    outcome: LookupOutcome::ResultCode(code),
                    ..
                })) => {
                    break Err(format!(
                        "publication namespace Identity lookup returned code {code}"
                    )
                    .into());
                }
                Ok(Some(LookupProgress::Source(Progress::Unavailable(error)))) | Err(error) => {
                    break Err(Box::new(error) as Box<dyn Error>);
                }
                Ok(Some(LookupProgress::Source(Progress::WaitDeadline))) | Ok(None) => {
                    break Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "publication namespace Identity lookup stopped",
                    )
                    .into());
                }
                Ok(Some(LookupProgress::Source(Progress::Lost { cause, .. }))) => {
                    break Err(
                        format!("publication namespace Identity source lost: {cause:?}").into(),
                    );
                }
                Ok(Some(LookupProgress::Finished { .. } | LookupProgress::Closed)) => {
                    break Err(
                        "selected publication namespace Identity did not return the exact ego"
                            .into(),
                    );
                }
                Ok(Some(_)) => {}
            }
        };
        let _retired = lookup.close();
        result
    }

    pub(super) async fn authorize(
        self,
        source: EndpointSource,
        until: u64,
        gate: &mut Gate,
    ) -> Result<Authorization> {
        let key = self.lookup(source, until, gate).await?;
        if key.key_type() != KeyType::Eddsa {
            return Err("publication namespace requires an EdDSA Identity ego".into());
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&key.expose_serialized()[4..]);
        Ok(Authorization {
            secret: EdkeySecret::from_seed(*seed),
            label: self.label,
            update: self.update,
        })
    }
}

pub(in crate::fs::publish) struct Authorization {
    secret: EdkeySecret,
    label: Vec<u8>,
    update: Option<Vec<u8>>,
}

impl Authorization {
    pub(in crate::fs::publish) fn uri(&self) -> Result<Vec<u8>> {
        let public = EddsaPublicKey::from_bytes(self.secret.public_key());
        let uri = Uri::Namespace(Namespace::new(public, &self.label)?);
        let mut bytes = vec![0; uri.encoded_len()?];
        if bytes.len() > UriLimits::default().max_input_bytes {
            return Err("namespace URI exceeds its encoded limit".into());
        }
        uri.encode(&mut bytes)?;
        Ok(bytes)
    }

    pub(in crate::fs::publish) async fn publish_content(
        &self,
        source: EndpointSource,
        uri: Uri<'_>,
        root_metadata: &[u8],
        options: UblockOptions,
        graph_root: Option<&Path>,
        gate: &mut Gate,
    ) -> Result<()> {
        let limits = metadata::Limits::default();
        let metadata::Decoded::Present(decoded) =
            metadata::decode_uncompressed(root_metadata, limits, metadata::Mode::Strict)?
        else {
            return Err("namespace root metadata must be present".into());
        };
        let items: Vec<_> = decoded.items().collect();
        let mut order = vec![0; items.len()];
        let mut scratch = vec![0; root_metadata.len()];
        let plan = metadata::plan_uncompressed(
            &items,
            &mut order,
            &mut scratch,
            limits,
            metadata::Options {
                compression: metadata::Compression::Never,
                max_output_bytes: Policy::default().max_metadata_bytes,
                ..Default::default()
            },
        )?;
        self.publish(source, uri, Some(&plan), options, graph_root, gate)
            .await
    }

    pub(super) async fn publish(
        &self,
        source: EndpointSource,
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        graph_root: Option<&Path>,
        gate: &mut Gate,
    ) -> Result<()> {
        let update = match (&self.update, graph_root) {
            (None, None) => None,
            (Some(label), Some(root)) => Some((label, graph(root, self.secret.public_key())?)),
            _ => return Err("missing namespace graph selection".into()),
        };
        let stop = Arc::clone(&gate.stop);
        let hard = gate.hard;
        let write = async {
            let mut identity = StoreInstance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [ReservationSlot::default(); 1];
            let store = crate::fs::service::datastore_client(
                &mut identity,
                &mut slots,
                &mut reservations,
                source,
            )?;
            let mut buffers = Buffers::new();
            let control = move |_| {
                if stop.load(Ordering::Acquire) || std::time::Instant::now() >= hard {
                    Control::Cancel
                } else {
                    Control::Continue
                }
            };
            let result = if let Some((label, mut graph)) = update {
                buffers
                    .store_identity_namespace(
                        store,
                        &self.secret,
                        &mut graph,
                        &self.label,
                        label,
                        uri,
                        metadata,
                        options,
                        control,
                    )
                    .await?
                    .publication
            } else {
                buffers
                    .store_namespace(
                        store,
                        &self.secret,
                        &self.label,
                        b"",
                        uri,
                        metadata,
                        options,
                        control,
                    )
                    .await?
            };
            if let Some(error) = result.cleanup {
                return Err(error.into());
            }
            Ok(())
        };
        let mut write = std::pin::pin!(write);
        poll_fn(|cx| {
            gate.poll(cx);
            write.as_mut().poll(cx)
        })
        .await
    }
}

fn graph(root: &Path, public: [u8; 32]) -> Result<Graph> {
    std::fs::create_dir_all(root)?;
    let path = root.join(crate::fs::publication::hex(&public));
    let limits = GraphLimits::default();
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Graph::open(path, public, limits, Default::default())?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(Graph::create(path, public, limits, Default::default())?)
        }
        Err(error) => Err(error.into()),
    }
}
