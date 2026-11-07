//! Streaming native directory publication and parent-authenticated inspection.
use super::{Download, DownloadOptions, DownloadSink, Error};
use crate::{Buffers, Control, Progress, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    content::VerifiedChunk,
    directory::{self as dir, SourceParser, Status, VerifiedDirectory, VerifiedEntry},
};
use gnunet_fs_codec::Inflate;
#[cfg(feature = "network")]
use {
    super::{PublishOptions, StoredFile},
    gnunet_datastore_host::Client,
    std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    },
    tokio::io::{AsyncRead, ReadBuf},
};

// Parser state, one reusable carry arena and one metadata arena. Entry views
// cannot escape their callback; the parser alone mints parent-bound membership.
struct DirectorySink<'buffers, Visit> {
    parser: SourceParser<'buffers>,
    metadata: &'buffers mut Vec<u8>,
    replacement: Option<&'buffers mut Vec<u8>>,
    max_record_bytes: usize,
    inflater: Inflate,
    visit: Visit,
    grown: bool,
}
impl<Visit> DownloadSink for DirectorySink<'_, Visit>
where
    Visit: FnMut(VerifiedEntry<'_>) -> crate::Result<()>,
{
    async fn chunk(&mut self, chunk: VerifiedChunk<'_>) -> Result<(), Error> {
        let mut local = 0;
        loop {
            let progress = self
                .parser
                .feed(&chunk, local, self.metadata, &mut self.inflater)
                .map_err(crate::Error::from)?;
            local += progress.consumed;
            if let Some(entry) = progress.entry() {
                (self.visit)(entry)?;
            }
            match progress.status() {
                Status::Event(_) => {}
                Status::NeedMore { .. } => break,
                Status::NeedRecord { required } => {
                    if *required > self.max_record_bytes {
                        return Err(crate::Error::Limit.into());
                    }
                    let buffer = self.replacement.take().ok_or(crate::Error::Limit)?;
                    crate::resize(buffer, self.max_record_bytes, 0)?;
                    self.parser
                        .replace_buffer(buffer.as_mut_slice())
                        .map_err(crate::Error::from)?;
                    self.grown = true;
                }
                Status::NeedPlain { required } => {
                    let required = *required;
                    crate::resize(self.metadata, required, 0)?;
                }
                Status::Complete(_) => break,
                Status::Partial(_) => return Err(crate::Error::Corrupt.into()),
            }
        }
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.parser.completion().ok_or(crate::Error::Corrupt)?;
        Ok(())
    }
}

#[cfg(feature = "network")]
struct PlannedInput<'plan, 'source> {
    plan: &'plan dir::BuildPlan<'source>,
    offset: u64,
}
#[cfg(feature = "network")]
impl AsyncRead for PlannedInput<'_, '_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let length = this
            .plan
            .read_at(this.offset, output.initialize_unfilled())
            .map_err(io::Error::other)?;
        this.offset += length as u64;
        output.advance(length);
        Poll::Ready(Ok(()))
    }
}

impl Buffers {
    /// Retrieve an actual directory CHK through the ordinary network download
    /// owner and lend strict parent-authenticated entries to the caller. Cache,
    /// original deadline, MQ cancellation and block authentication are shared
    /// with `download`. No directory-sized plaintext collection is created.
    ///
    /// Entry callbacks establish only authenticated membership in this parent;
    /// later syntax/transfer failure can leave a valid delivered prefix. The
    /// returned receipt requires both the whole CHK tree and complete strict
    /// directory syntax. It makes no recursive-child or filesystem claim.
    #[expect(
        clippy::too_many_arguments,
        reason = "Matches the streaming directory API with explicit native lookup, directory policy and lending callbacks"
    )]
    pub async fn download_directory(
        &mut self,
        source: EndpointSource,
        content: Content,
        cache: Option<&mut Repository>,
        options: DownloadOptions,
        directory_limits: dir::Limits,
        control: impl FnMut(Progress) -> Control,
        visit: impl FnMut(VerifiedEntry<'_>) -> crate::Result<()>,
    ) -> Result<VerifiedDirectory, Error> {
        if content.size > directory_limits.max_extent {
            return Err(crate::Error::from(dir::Error::Limit).into());
        }
        self.prepare(content, options.limits)?;
        let mut larger = Vec::new();
        let (result, grown) = {
            let mut transfer = Download::new(
                source,
                content,
                cache,
                options,
                &mut self.keys,
                &mut self.plain,
                &mut self.encoded,
            )?;
            let mut sink = DirectorySink {
                parser: SourceParser::new(content, &mut self.record, directory_limits)
                    .map_err(crate::Error::from)?,
                metadata: &mut self.metadata_plain,
                replacement: Some(&mut larger),
                max_record_bytes: directory_limits
                    .max_record_bytes
                    .min(usize::try_from(content.size).unwrap_or(usize::MAX)),
                inflater: Inflate::new(),
                visit,
                grown: false,
            };
            let result = transfer.run(&mut sink, control).await.and_then(|_| {
                sink.parser
                    .completion()
                    .ok_or_else(|| crate::Error::Corrupt.into())
            });
            (result, sink.grown)
        };
        // Retain an admitted larger reusable arena even after a transfer error.
        if grown {
            self.record = larger;
        }
        result
    }

    /// Stream a checked directory plan through the ordinary real DATASTORE
    /// publication owner. This retains its exact ACK/uncertainty, reservation,
    /// deadline and cleanup semantics. Only protocol-sized buffers are used.
    /// Known partial-plan selection stays visible in `plan.report()`; the
    /// returned StoredFile describes exactly that selected artifact.
    #[cfg(feature = "network")]
    pub async fn store_directory<'id>(
        &mut self,
        plan: &dir::BuildPlan<'_>,
        store: Client<'id, '_, '_>,
        options: PublishOptions,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<StoredFile, Error> {
        self.store_directory_tracked(
            plan,
            store,
            options,
            &mut Progress::default(),
            &mut 0,
            control,
        )
        .await
    }

    // The recursive publisher must retain the real acknowledged prefix on an
    // error before the next callback. The shared publisher owns those counters.
    #[cfg(feature = "network")]
    pub(super) async fn store_directory_tracked<'id>(
        &mut self,
        plan: &dir::BuildPlan<'_>,
        store: Client<'id, '_, '_>,
        options: PublishOptions,
        progress: &mut Progress,
        stored_bytes: &mut u128,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<StoredFile, Error> {
        let mut input = PlannedInput { plan, offset: 0 };
        self.store_file_tracked(
            &mut input,
            plan.report().wire_bytes,
            store,
            options,
            progress,
            stored_bytes,
            control,
        )
        .await
    }
}
