use crate::{BlockSink, BlockSource, Buffers, Control, Error, Limits, Progress, Published, Result};
use gnunet_fs::{
    Content,
    content::FileReader,
    directory::{self as dir, SourceParser, Status, VerifiedDirectory, VerifiedEntry},
};
use gnunet_fs_codec::Inflate;

impl Buffers {
    /// Encode/store a complete prepared directory using the same fixed block
    /// buffers as a file import, without a complete directory output allocation.
    pub fn publish_directory(
        &mut self,
        plan: &dir::BuildPlan<'_>,
        sink: &mut impl BlockSink,
        limits: Limits,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Published> {
        struct Input<'p, 's> {
            plan: &'p dir::BuildPlan<'s>,
            offset: u64,
        }
        impl std::io::Read for Input<'_, '_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let length = self
                    .plan
                    .read_at(self.offset, output)
                    .map_err(std::io::Error::other)?;
                self.offset += length as u64;
                Ok(length)
            }
        }
        let mut input = Input { plan, offset: 0 };
        self.publish(&mut input, plan.report().wire_bytes, sink, limits, control)
    }
    /// Stream an authenticated directory and lend its actual parent-bound entry
    /// records to the owner. The callback can admit them to walk::Walk without
    /// collecting the whole directory or copying every entry's metadata.
    pub fn visit_directory(
        &mut self,
        source: &mut impl BlockSource,
        content: Content,
        limits: Limits,
        directory_limits: dir::Limits,
        visit: impl FnMut(VerifiedEntry<'_>) -> Result<()>,
    ) -> Result<VerifiedDirectory> {
        self.visit_directory_controlled(
            source,
            content,
            limits,
            directory_limits,
            |_| Control::Continue,
            visit,
        )
    }
    /// Directory streaming with cancellation sampled before each actual block
    /// request, including long metadata and padding with no entry callbacks.
    pub fn visit_directory_controlled(
        &mut self,
        source: &mut impl BlockSource,
        content: Content,
        limits: Limits,
        directory_limits: dir::Limits,
        mut control: impl FnMut(Progress) -> Control,
        mut visit: impl FnMut(VerifiedEntry<'_>) -> Result<()>,
    ) -> Result<VerifiedDirectory> {
        if content.size > directory_limits.max_extent {
            return Err(dir::Error::Limit.into());
        }
        self.prepare(content, limits)?;
        let mut reader = FileReader::new(content, &mut self.keys)?;
        let mut larger = Vec::new();
        let mut replacement = Some(&mut larger);
        let mut grown = false;
        let result = {
            let mut parser = SourceParser::new(content, &mut self.record, directory_limits)?;
            let mut inflater = Inflate::new();
            let mut complete = false;
            let mut work = Progress::default();
            while let Some(request) = reader.next() {
                if control(work) == Control::Cancel {
                    return Err(Error::Cancelled);
                }
                let length = source.read_block(request, &mut self.encoded)?;
                let ciphertext = self.encoded.get(..length).ok_or(Error::Corrupt)?;
                let opened = reader.open_next(ciphertext, &mut self.plain)?;
                work.blocks += 1;
                work.encoded_bytes += length as u128;
                let Some(chunk) = opened else {
                    continue;
                };
                work.plaintext_bytes += chunk.bytes().len() as u64;
                let mut local = 0;
                loop {
                    let progress =
                        parser.feed(&chunk, local, &mut self.metadata_plain, &mut inflater)?;
                    local += progress.consumed;
                    if let Some(entry) = progress.entry() {
                        visit(entry)?;
                    }
                    match progress.status() {
                        Status::Event(_) => {}
                        Status::NeedMore { .. } => break,
                        Status::NeedRecord { required } => {
                            let cap = directory_limits
                                .max_record_bytes
                                .min(usize::try_from(content.size).unwrap_or(usize::MAX));
                            if *required > cap {
                                return Err(Error::Limit);
                            }
                            let buffer = replacement.take().ok_or(Error::Limit)?;
                            crate::resize(buffer, cap, 0)?;
                            parser.replace_buffer(buffer.as_mut_slice())?;
                            grown = true;
                        }
                        Status::NeedPlain { required } => {
                            let required = *required;
                            crate::resize(&mut self.metadata_plain, required, 0)?;
                        }
                        Status::Complete(_) => {
                            complete = true;
                            break;
                        }
                        Status::Partial(_) => return Err(Error::Corrupt),
                    }
                }
            }
            if !complete || reader.completion().is_none() {
                return Err(Error::Corrupt);
            }
            parser.completion().ok_or(Error::Corrupt)?
        };
        if grown {
            self.record = larger;
        }
        Ok(result)
    }
}
