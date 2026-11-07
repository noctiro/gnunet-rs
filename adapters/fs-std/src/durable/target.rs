//! Durable output policy for the single source-authenticated native tree driver.
use super::{
    Cause, CommitFailure, codec,
    model::{EntryBinding, Event, TempFact},
    task::{Session, lock},
};
use crate::network::tree_download::{
    TreeDownloadOptions, TreeDownloadProgress, driver, inline::InlineBlocks, paths::Job,
};
use crate::output::{OutputObservation, TempRecord};
use crate::search::proof::NamespaceProof;
use crate::{
    Buffers, CommitStage, Control, Error, FileIdentity, OWNER_MARKER_NAME, OutputDir, ReadFile,
    Repository,
};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content, Namespace,
    directory::{VerifiedDirectory, walk},
};
use gnunet_types::AbsoluteTime;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    sync::Mutex,
};

pub(super) struct Target<'a> {
    state: &'a Mutex<Session>,
    output: &'a mut OutputDir,
    visited: BTreeSet<[u8; 64]>,
}
impl<'a> Target<'a> {
    pub fn new(state: &'a Mutex<Session>, output: &'a mut OutputDir) -> Self {
        Self {
            state,
            output,
            visited: BTreeSet::new(),
        }
    }
    fn binding(&mut self, job: &Job, content: Content) -> Result<EntryBinding, Cause> {
        if job.path.file_name() == Some(OsStr::new(OWNER_MARKER_NAME)) {
            return Err(Cause::Reconcile {
                path: job.path.as_ref().clone(),
                reason: "name is reserved for durable task ownership",
            });
        }
        let binding = EntryBinding {
            id: job.id,
            parent: job.parent,
            path: job.path.as_ref().clone(),
            kind: job.kind,
            content,
        };
        lock(self.state)?.state.entry(&binding)?;
        self.visited.insert(job.id);
        Ok(binding)
    }
    fn owner(&self, id: [u8; 64]) -> Result<[u8; 32], Cause> {
        let s = lock(self.state)?;
        if s.state
            .entries
            .get(&id)
            .is_some_and(|e| e.binding.parent.is_none())
        {
            return Ok(*s.store.task_id());
        }
        let mut hash = gnunet_crypto::Hash512State::new();
        hash.update(b"GNUnet Rust durable directory owner v1\0");
        hash.update(s.store.task_id());
        hash.update(&id);
        let mut result = [0; 32];
        result.copy_from_slice(&hash.finish()[..32]);
        Ok(result)
    }
    fn clean(
        &mut self,
        binding: &EntryBinding,
        temporary: &TempFact,
        stage: CommitStage,
    ) -> Result<(), Cause> {
        let parent = binding
            .path
            .parent()
            .ok_or(Cause::State("file has no parent"))?;
        let relative = parent.join(&temporary.name);
        self.output
            .cleanup_recorded_temp(&relative, temporary.parent, temporary.identity)?;
        lock(self.state)?.append(Event::Cleanup {
            id: binding.id,
            success: true,
            stage,
        })
    }
    fn record(
        state: &Mutex<Session>,
        binding: &EntryBinding,
        observation: OutputObservation<'_>,
    ) -> Result<(), Cause> {
        let check = |temp: TempRecord<'_>| -> Result<(), Cause> {
            if temp.content != binding.content {
                return Err(Cause::State("observer content differs from original entry"));
            }
            Ok(())
        };
        let mut session = lock(state)?;
        match observation {
            OutputObservation::TempOwned(temporary) => {
                check(temporary)?;
                session.append(Event::TempOwned {
                    binding: binding.clone(),
                    temporary: TempFact {
                        parent: temporary.parent,
                        identity: temporary.identity,
                        name: temporary.name.to_owned(),
                    },
                })
            }
            OutputObservation::CommitIntent {
                temporary,
                final_name,
                final_parent,
            } => {
                check(temporary)?;
                if binding.path.file_name() != Some(final_name) || final_parent != temporary.parent
                {
                    return Err(Cause::State("commit name differs from original entry"));
                }
                session.append(Event::CommitIntent { id: binding.id })
            }
            OutputObservation::FileCommitted {
                temporary,
                final_name,
                identity,
                receipt,
                final_parent,
            } => {
                check(temporary)?;
                if binding.path.file_name() != Some(final_name)
                    || receipt.verified.content() != binding.content
                    || final_parent != temporary.parent
                {
                    return Err(Cause::State(
                        "committed receipt differs from original entry",
                    ));
                }
                session.new_files += 1;
                session.append(Event::FileCommitted {
                    id: binding.id,
                    identity,
                })
            }
            OutputObservation::Cleanup {
                temporary,
                stage,
                outcome,
            } => {
                check(temporary)?;
                session.append(Event::Cleanup {
                    id: binding.id,
                    success: outcome.is_ok(),
                    stage,
                })
            }
        }
    }
    fn snapshot(&self, binding: &EntryBinding) -> Result<Option<super::model::EntryState>, Cause> {
        Ok(lock(self.state)?.state.entry(binding)?.cloned())
    }
    fn confirmed(
        &mut self,
        binding: &EntryBinding,
        identity: FileIdentity,
        buffers: &mut Buffers,
        cache: &mut Repository,
        limits: crate::Limits,
        control: &mut impl FnMut(crate::Progress) -> Control,
    ) -> Result<crate::RevalidatedFile, Cause> {
        let parent = lock(self.state)?
            .state
            .entries
            .get(&binding.parent.ok_or(Cause::State("file parent missing"))?)
            .and_then(|e| e.created)
            .ok_or(Cause::State("file parent is not attached"))?;
        let read = self
            .output
            .revalidate_file(
                &binding.path,
                binding.content,
                identity,
                Some(parent),
                buffers,
                cache,
                limits,
                control,
            )
            .map_err(Cause::Revalidate)?;
        lock(self.state)?.revalidated += 1;
        Ok(read)
    }
}
impl driver::Target for Target<'_> {
    type Failure = Cause;
    fn begin(&mut self) -> Result<bool, Cause> {
        let state = lock(self.state)?;
        if state.state.root != Some(self.output.identity()?) {
            return Err(Cause::State("attached output identity changed"));
        }
        Ok(false)
    }
    fn directory(&mut self, job: &Job, content: Content) -> Result<bool, Cause> {
        let binding = self.binding(job, content)?;
        let known = self.snapshot(&binding)?;
        if !known.as_ref().is_some_and(|e| e.directory_intent) {
            lock(self.state)?.append(Event::DirectoryIntent(binding.clone()))?;
        }
        let expected = known.as_ref().and_then(|e| e.created);
        let owner = self.owner(binding.id)?;
        let (directory, created) = match self.output.attach_owned_directory(
            &binding.path,
            owner,
            expected,
        ) {
            Ok(directory) => (directory, false),
            Err(error)
                if expected.is_none()
                    && matches!(&error.operation,Error::Io(e) if e.kind()==std::io::ErrorKind::NotFound) =>
            {
                (
                    self.output
                        .create_owned_directory(&binding.path, owner)
                        .map_err(|error| Cause::Directory(Box::new(error)))?,
                    true,
                )
            }
            Err(error) => return Err(Cause::Directory(Box::new(error))),
        };
        let identity = directory.identity()?;
        if expected.is_none() {
            lock(self.state)?.append(Event::DirectoryCreated {
                id: binding.id,
                identity,
            })?;
        }
        Ok(created)
    }
    fn directory_verified(&mut self, job: &Job, receipt: VerifiedDirectory) -> Result<(), Cause> {
        let binding = self.binding(job, receipt.content())?;
        if !self.snapshot(&binding)?.is_some_and(|e| e.verified) {
            lock(self.state)?.append(Event::DirectoryVerified { id: binding.id })?;
        }
        Ok(())
    }
    async fn file(
        &mut self,
        job: &Job,
        content: Content,
        source: &EndpointSource,
        buffers: &mut Buffers,
        cache: Option<&mut Repository>,
        options: crate::network::DownloadOptions,
        inline: Option<&mut InlineBlocks>,
        control: &mut impl FnMut(crate::Progress) -> Control,
    ) -> Result<ReadFile, Cause> {
        let binding = self.binding(job, content)?;
        let cache = cache.ok_or(Cause::State(
            "durable runs require an explicit authenticated repository",
        ))?;
        if let Some(known) = self.snapshot(&binding)? {
            if let Some(identity) = known.committed {
                if let Some(temp) = known.temporary.as_ref().filter(|_| !known.cleanup) {
                    self.clean(&binding, temp, CommitStage::Durable)?;
                }
                return Ok(self
                    .confirmed(&binding, identity, buffers, cache, options.limits, control)?
                    .read);
            }
            if let Some(temp) = &known.temporary {
                let final_id = self.output.inspect_file(&binding.path)?;
                if let Some(identity) = final_id {
                    if !known.intent || identity != temp.identity {
                        return Err(Cause::Reconcile {
                            path: binding.path.clone(),
                            reason: "uncommitted final name differs from original intent inode",
                        });
                    }
                    let verified = self.confirmed(
                        &binding,
                        identity,
                        buffers,
                        cache,
                        options.limits,
                        control,
                    )?;
                    if let Err(cause) = lock(self.state)?.append(Event::FileCommitted {
                        id: binding.id,
                        identity,
                    }) {
                        return Err(Cause::Committed(Box::new(CommitFailure {
                            identity,
                            receipt: verified.read,
                            cause: Box::new(cause),
                        })));
                    }
                    if let Err(cause) = self.clean(&binding, temp, CommitStage::Durable) {
                        return Err(Cause::Committed(Box::new(CommitFailure {
                            identity,
                            receipt: verified.read,
                            cause: Box::new(cause),
                        })));
                    }
                    return Ok(verified.read);
                }
                self.clean(&binding, temp, known.stage)?;
                lock(self.state)?.append(Event::ResetPending { id: binding.id })?;
            }
        }
        let session = self.state;
        let observe = |event: OutputObservation<'_>| Self::record(session, &binding, event);
        // The observer and control access the same original writer through short
        // synchronous mutex borrows; no guard crosses an await.
        let mut result = match inline {
            Some(blocks) => self.output.write_file_observed(
                &binding.path,
                blocks,
                content,
                buffers,
                options.limits,
                control,
                observe,
            ),
            None => {
                self.output
                    .download_file_observed(
                        &binding.path,
                        source
                            .duplicate()
                            .map_err(crate::network::Error::from)
                            .map_err(Error::from)?,
                        content,
                        buffers,
                        Some(cache),
                        options,
                        control,
                        observe,
                    )
                    .await
            }
        };
        // A live pre-link refusal has retired its original output work. Settle
        // only after checking the actual final name, never from NotLinked alone.
        if let Err(error) = &mut result
            && error.stage == CommitStage::NotLinked
            && error.observer.is_none()
            && error.cleanup.is_none()
            && self
                .snapshot(&binding)?
                .is_some_and(|e| e.intent && e.committed.is_none() && e.cleanup)
        {
            let settled = match self.output.inspect_file(&binding.path) {
                Ok(None) => lock(self.state)?.append(Event::ResetPending { id: binding.id }),
                Ok(Some(_)) => Err(Cause::Reconcile {
                    path: binding.path.clone(),
                    reason: "final name appeared before original link",
                }),
                Err(cause) => Err(cause.into()),
            };
            if let Err(cause) = settled {
                error.observer = Some(cause);
            }
        }
        result.map_err(Cause::Output)
    }
    async fn namespace(
        &mut self,
        job: &Job,
        source: &EndpointSource,
        namespace: Namespace<'_>,
        options: TreeDownloadOptions,
        progress: TreeDownloadProgress,
        last: &mut Option<AbsoluteTime>,
        control: &mut impl FnMut(TreeDownloadProgress) -> Control,
        cleanup: &mut Option<crate::search::Error>,
    ) -> Result<(Content, [u8; 32]), Cause> {
        let saved = lock(self.state)?
            .state
            .entries
            .get(&job.id)
            .and_then(|e| e.selection);
        if let Some(saved) = saved {
            let binding = self.binding(job, saved.selected)?;
            let mut state = lock(self.state)?;
            let record = state
                .store
                .read_record(saved.record_index)?
                .ok_or(Cause::State("selection record missing"))?;
            let view = codec::selection_view(record.kind, record.bytes)?;
            if view.binding != binding
                || view.selected != saved.selected
                || view.location != saved.location
            {
                return Err(Cause::State("selection record binding changed"));
            }
            let block = gnunet_fs::ublock::Limits {
                uri: options.directory.uri,
                ..Default::default()
            };
            let proof = NamespaceProof::decode(view.proof, options.namespace, block)
                .map_err(Error::from)?;
            proof
                .verify(
                    namespace,
                    saved.selected,
                    saved.location,
                    options.namespace,
                    block,
                )
                .map_err(Error::from)?;
            return Ok((
                saved.selected,
                saved.location.map_or([0; 32], |loc| *loc.peer().as_bytes()),
            ));
        }
        let mut selected =
            super::namespace::select(source, namespace, options, progress, last, control, cleanup)
                .await?;
        *cleanup = selected.cleanup.take();
        let binding = self.binding(job, selected.selected)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(selected.proof.encoded_len().map_err(Error::from)?)
            .map_err(|_| Error::Limit)?;
        bytes.resize(selected.proof.encoded_len().map_err(Error::from)?, 0);
        selected.proof.encode(&mut bytes).map_err(Error::from)?;
        let recorded = lock(self.state)?.append(Event::NamespaceSelected {
            binding: Box::new(binding),
            selected: selected.selected,
            location: selected.location,
            proof: &bytes,
        });
        recorded?;
        if let Some(error) = cleanup.take() {
            return Err(Error::from(error).into());
        }
        Ok((
            selected.selected,
            selected
                .location
                .map_or([0; 32], |loc| *loc.peer().as_bytes()),
        ))
    }
    fn known_commit(error: &Cause) -> bool {
        error.committed()
    }
    fn finish(&mut self) -> Result<(), Cause> {
        let (entries, limit) = {
            let state = lock(self.state)?;
            if state.state.entries.len() != self.visited.len()
                || state
                    .state
                    .entries
                    .keys()
                    .any(|id| !self.visited.contains(id))
            {
                return Err(Cause::State(
                    "some historical entries were not reached from authenticated parents",
                ));
            }
            let mut entries = BTreeMap::new();
            for e in state.state.entries.values() {
                let identity = match e.binding.kind {
                    walk::Kind::Directory => e.created,
                    walk::Kind::File => e.committed,
                }
                .ok_or(Cause::State("output entry is incomplete"))?;
                if e.binding.kind == walk::Kind::File
                    && (!e.cleanup || e.stage != CommitStage::Durable)
                {
                    return Err(Cause::State(
                        "output cleanup or commit requires reconciliation",
                    ));
                }
                entries.insert(e.binding.path.clone(), (identity, e.binding.kind));
            }
            (
                entries,
                state
                    .state
                    .manifest
                    .options
                    .max_entries
                    .checked_add(1)
                    .ok_or(Error::Limit)?,
            )
        };
        for (path, (identity, kind)) in &entries {
            if *kind != walk::Kind::Directory {
                continue;
            }
            if self.output.directory_identity(path)? != *identity {
                return Err(Cause::Reconcile {
                    path: path.clone(),
                    reason: "directory identity changed",
                });
            }
            let mut refused = None;
            let mut marker = false;
            let scanned = self
                .output
                .visit_children(path, limit, |name, actual, is_dir| {
                    if name == OsStr::new(OWNER_MARKER_NAME) {
                        marker = true;
                        return Ok(());
                    }
                    let child = path.join(name);
                    match entries.get(&child) {
                        Some((expected, kind))
                            if actual == *expected
                                && is_dir == (*kind == walk::Kind::Directory) =>
                        {
                            Ok(())
                        }
                        _ => {
                            refused = Some(Cause::Reconcile {
                                path: child,
                                reason: "unclaimed or replaced output entry retained",
                            });
                            Err(Error::SourceChanged)
                        }
                    }
                });
            if let Some(error) = refused {
                return Err(error);
            }
            scanned?;
            if !marker {
                return Err(Cause::Reconcile {
                    path: path.clone(),
                    reason: "task owner marker is missing",
                });
            }
        }
        self.output.sync_directory()?;
        Ok(())
    }
}
