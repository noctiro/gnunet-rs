//! CHK measurement through ordinary file/tree encoding without a storage owner.
use super::{Failure, Limits, Policy, extraction_limits, finish};
use crate::{
    Buffers, Control, Progress,
    extraction::{self, Budget, Context, MetadataSettings, descriptor_info},
    input_tree::InputDir,
    publication::plan::{
        self,
        tree::{Event, MeasuredObject, MetadataProvider, Observer, emit, root_file_progress},
    },
};
use std::{
    cell::{Cell, RefCell},
    fs::{self, File},
    path::Path,
};

struct Metadata<'a, C>(extraction::Extractor<'a, C>);

impl<C: FnMut(Progress) -> Control> MetadataProvider for Metadata<'_, C> {
    fn prepare(
        &mut self,
        source: &File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, plan::Error> {
        Ok(self
            .0
            .extract_one(source, relative, directory, base, max_bytes)?
            .wire)
    }
}

/// Compute exact CHK values with ordinary selected publication metadata. Work
/// is bounded and cancellable. This operation owns no repository or service.
pub fn simulate(
    input: &Path,
    buffers: &mut Buffers,
    limits: Limits,
    mut policy: Policy,
    metadata: MetadataSettings,
    mut observer: Observer<'_>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Vec<MeasuredObject>, Failure> {
    policy.metadata.extract &= metadata.automatic_keywords_enabled();
    policy.validate(limits)?;
    let settings_bytes = metadata.retained_bytes()?;
    let plan_limits = plan::Limits {
        max_plan_bytes: limits
            .plan
            .max_plan_bytes
            .min(policy.max_group_plan_bytes)
            .checked_sub(settings_bytes)
            .ok_or(Failure::Policy)?,
        ..limits.plan
    };
    let context = Context {
        control: RefCell::new(control),
        progress: Cell::new(Progress::default()),
        budget: RefCell::new(Budget {
            used: settings_bytes,
            limit: policy.max_group_plan_bytes,
        }),
    };
    context.check()?;
    let observed = fs::symlink_metadata(input)?;
    if observed.file_type().is_symlink() || (!observed.is_dir() && !observed.is_file()) {
        return Err(Failure::Policy);
    }
    let mut extractor = Metadata(extraction::Extractor::new(
        input,
        policy.metadata,
        extraction_limits(limits),
        &context,
        &metadata,
    )?);
    extractor.0.content_file_bytes = if observed.is_dir() {
        limits.plan.tree.max_file_bytes
    } else {
        limits.plan.file.max_file_bytes
    };
    extractor.0.manual = metadata.manual();
    extractor.0.provider =
        metadata.open(&context, policy.metadata, extractor.0.content_file_bytes)?;
    let result = if observed.is_dir() {
        InputDir::open(input)
            .map_err(|error| {
                plan::Error::from(crate::network::tree_publish::TreePublishCause::Source(
                    error,
                ))
            })
            .and_then(|directory| {
                plan::tree::measure_tree_observed(
                    &directory,
                    input,
                    buffers,
                    plan_limits,
                    &mut extractor,
                    observer.take(),
                    |p| context.report(p),
                )
            })
            .map_err(Failure::from)
    } else {
        (|| -> Result<Vec<MeasuredObject>, Failure> {
            let mut file = crate::input::open_exact(input)?;
            let original = crate::input::file_info(&file)?;
            if original.bytes > plan_limits.file.max_file_bytes {
                return Err(plan::Error::Limit.into());
            }
            emit(
                &mut observer,
                Event::Scanning {
                    relative: Path::new(""),
                    directory: false,
                },
            )?;
            emit(&mut observer, Event::ScanComplete)?;
            extractor.prepare(
                &file,
                Path::new(""),
                false,
                &[],
                policy.metadata.max_metadata_bytes,
            )?;
            emit(&mut observer, Event::Extracted(Path::new("")))?;
            emit(&mut observer, Event::MetadataComplete)?;
            let (content, _) = buffers
                .measure(
                    &mut file,
                    original.bytes,
                    plan_limits.file,
                    root_file_progress(&mut observer, original.bytes, |p| context.report(p)),
                )
                .map_err(plan::Error::from)?;
            if descriptor_info(&file)? != original
                || crate::input::file_info(&crate::input::open_exact(input)?)? != original
            {
                return Err(plan::Error::from(crate::Error::SourceChanged).into());
            }
            context.check()?;
            Ok(vec![MeasuredObject {
                relative: Default::default(),
                content,
            }])
        })()
    };
    finish(extractor.0.provider.take(), result)
}
