//! Bounded bottom-up share-tree trimming for the official metadata preview.
use super::{
    Budget, Control, Error, ExtractedObject, InspectionEvent, InspectionFailure, InspectionReport,
    Limits, ManualMetadata, MetadataSettings, Policy, Progress, Value, copy, decoded,
    encode_values, inspect_observed, md,
};
use std::{
    collections::{HashMap, HashSet},
    mem::size_of,
    path::Path,
};

#[derive(Default)]
struct Links {
    last: Option<usize>,
    previous: Option<usize>,
}

struct Node {
    object: ExtractedObject,
    links: Links,
}

struct Tree {
    nodes: Vec<Node>,
    parents: Vec<usize>,
    budget: Budget,
}

impl Tree {
    fn push(&mut self, object: ExtractedObject) -> Result<(), Error> {
        let extra = size_of::<Node>() - size_of::<ExtractedObject>();
        let owned = object
            .retained_bytes()?
            .checked_add(extra)
            .ok_or(Error::Limit)?;
        self.budget.add(owned)?;
        self.nodes.try_reserve(1).map_err(|_| Error::Limit)?;
        let index = self.nodes.len();
        let mut links = Links::default();
        if let Some(parent) = object.relative.parent() {
            while self
                .parents
                .last()
                .is_some_and(|&i| self.nodes[i].object.relative.as_path() != parent)
            {
                let _closed = self.parents.pop();
            }
            let parent = *self.parents.last().ok_or(Error::Binding)?;
            links.previous = self.nodes[parent].links.last.replace(index);
        } else if index != 0 || !object.relative.as_os_str().is_empty() {
            return Err(Error::Binding);
        }
        if object.directory {
            self.parents.try_reserve(1).map_err(|_| Error::Limit)?;
            self.parents.push(index);
        }
        self.nodes.push(Node { object, links });
        Ok(())
    }

    fn trim(
        &mut self,
        policy: Policy,
        user: Option<&[u8]>,
        control: &mut impl FnMut(Progress) -> Control,
    ) -> Result<(), Error> {
        for index in (0..self.nodes.len()).rev() {
            if control(Progress::default()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let (parents, children) = self.nodes.split_at_mut(index + 1);
            let current = &mut parents[index];
            if !current.object.directory {
                continue;
            }
            let previous = current.object.retained_bytes()?;
            let mut values = directory_values(&current.object, user, policy)?;
            current.object.keywords = Vec::new();
            let last = current.links.last;
            let offset = index + 1;
            let children = &mut Children {
                nodes: children,
                offset,
                last,
            };
            if children.indices().nth(1).is_some() {
                let mut workspace = Budget {
                    used: self.budget.used,
                    limit: self.budget.limit,
                };
                let moved = collect(children, policy, &mut workspace, control)?;
                self.budget.replace(moved.released_keyword_bytes, 0)?;
                for item in moved.metadata {
                    insert(&mut values, item, policy)?;
                }
                current.object.keywords = moved.keywords;
            }
            current.object.metadata = encode_values(&values, policy)?;
            self.budget
                .replace(previous, current.object.retained_bytes()?)?;
        }
        Ok(())
    }
}

struct Children<'a> {
    nodes: &'a mut [Node],
    offset: usize,
    last: Option<usize>,
}

impl Children<'_> {
    fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        std::iter::successors(self.last, |index| {
            self.nodes[index - self.offset].links.previous
        })
        .map(|index| index - self.offset)
    }
}

struct Count<T> {
    item: T,
    count: usize,
}

struct Frequency<'a, T> {
    index: HashMap<&'a [u8], usize>,
    order: Vec<Count<T>>,
}

impl<'a, T> Frequency<'a, T> {
    fn new() -> Self {
        Self {
            index: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn count(&mut self, key: &'a [u8], item: T, budget: &mut Budget) -> Result<(), Error> {
        if let Some(&index) = self.index.get(key) {
            self.order[index].count = self.order[index].count.checked_add(1).ok_or(Error::Limit)?;
        } else {
            budget.add(size_of::<(&[u8], usize)>() + size_of::<Count<T>>())?;
            self.index.try_reserve(1).map_err(|_| Error::Limit)?;
            self.order.try_reserve(1).map_err(|_| Error::Limit)?;
            let _previous = self.index.insert(key, self.order.len());
            self.order.push(Count { item, count: 1 });
        }
        Ok(())
    }

    fn promoted(self, threshold: usize) -> impl Iterator<Item = T> {
        self.order
            .into_iter()
            .filter_map(move |count| (count.count >= threshold).then_some(count.item))
    }
}

struct Promotion {
    metadata: Vec<Value>,
    keywords: Vec<Vec<u8>>,
    released_keyword_bytes: usize,
}

fn collect(
    children: &mut Children<'_>,
    policy: Policy,
    budget: &mut Budget,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<Promotion, Error> {
    let mut metadata = Frequency::new();
    let mut keywords = Frequency::new();
    let mut count = 0usize;
    for index in children.indices() {
        if control(Progress::default()) == Control::Cancel {
            return Err(Error::Cancelled);
        }
        count = count.checked_add(1).ok_or(Error::Limit)?;
        let child = &children.nodes[index].object;
        for item in decoded(&child.metadata, policy)?.items() {
            metadata.count(item.data, item, budget)?;
        }
        for keyword in &child.keywords {
            keywords.count(keyword, keyword.as_slice(), budget)?;
        }
    }
    let threshold = 1 + count / 2;
    let mut copied = Vec::new();
    let mut moved = Vec::new();
    for item in metadata.promoted(threshold) {
        if copied.len() >= policy.max_metadata_items {
            return Err(Error::Limit);
        }
        budget.add(
            size_of::<Value>()
                + item.data.len()
                + item.plugin.map_or(0, <[u8]>::len)
                + item.mime.map_or(0, <[u8]>::len),
        )?;
        copied.try_reserve(1).map_err(|_| Error::Limit)?;
        copied.push(owned(item)?);
    }
    for keyword in keywords.promoted(threshold) {
        if moved.len() >= policy.max_keywords {
            return Err(Error::Limit);
        }
        budget.add(size_of::<Vec<u8>>() + keyword.len())?;
        moved.try_reserve(1).map_err(|_| Error::Limit)?;
        moved.push(copy(keyword)?);
    }
    let mut labels = HashSet::new();
    budget.add(
        moved
            .len()
            .checked_mul(size_of::<&[u8]>())
            .ok_or(Error::Limit)?,
    )?;
    labels.try_reserve(moved.len()).map_err(|_| Error::Limit)?;
    labels.extend(moved.iter().map(Vec::as_slice));
    let mut position = children.last;
    let mut removals = Vec::new();
    let mut released_keyword_bytes = 0usize;
    while let Some(index) = position {
        if control(Progress::default()) == Control::Cancel {
            return Err(Error::Cancelled);
        }
        let child = &mut children.nodes[index - children.offset];
        position = child.links.previous;
        removals.clear();
        removals
            .try_reserve(child.object.keywords.len())
            .map_err(|_| Error::Limit)?;
        removals.extend(
            child
                .object
                .keywords
                .iter()
                .filter_map(|label| labels.get(label.as_slice()).copied()),
        );
        for label in &removals {
            let Some(position) = child
                .object
                .keywords
                .iter()
                .position(|candidate| candidate.as_slice() == *label)
            else {
                return Err(Error::Binding);
            };
            let removed = child.object.keywords.swap_remove(position);
            released_keyword_bytes = released_keyword_bytes
                .checked_add(removed.capacity())
                .ok_or(Error::Limit)?;
        }
    }
    Ok(Promotion {
        metadata: copied,
        keywords: moved,
        released_keyword_bytes,
    })
}

fn owned(item: md::Item<'_>) -> Result<Value, Error> {
    Ok(Value {
        kind: item.kind,
        format: item.format,
        data: copy(item.data)?,
        mime: item.mime.map(copy).transpose()?,
        plugin: item.plugin.map(copy).transpose()?,
    })
}

fn insert(values: &mut Vec<Value>, value: Value, policy: Policy) -> Result<(), Error> {
    if let Some(existing) = values
        .iter_mut()
        .find(|item| item.kind == value.kind && item.data == value.data)
    {
        if existing.mime.is_none() {
            existing.mime = value.mime;
        }
        if existing.format == md::Format::CString && value.format == md::Format::Utf8 {
            existing.format = md::Format::Utf8;
        }
        return Ok(());
    }
    if values.len() >= policy.max_metadata_items {
        return Err(Error::Limit);
    }
    values.try_reserve(1).map_err(|_| Error::Limit)?;
    values.push(value);
    Ok(())
}

fn directory_values(
    object: &ExtractedObject,
    user: Option<&[u8]>,
    policy: Policy,
) -> Result<Vec<Value>, Error> {
    let mut values = Vec::new();
    for item in decoded(&object.metadata, policy)?.items() {
        if item.kind == 1 {
            continue;
        }
        let mut value = owned(item)?;
        if item.kind == 180
            && let Some(name) = item.text()
        {
            if user.is_some_and(|user| {
                name.get(..user.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(user))
            }) {
                continue;
            }
            if !name.ends_with(b"/") {
                value.data.try_reserve(1).map_err(|_| Error::Limit)?;
                value.data.truncate(name.len());
                value.data.extend_from_slice(b"/\0");
            }
            for byte in &mut value.data[..name.len()] {
                if *byte == b'\\' {
                    *byte = b'/';
                }
            }
        }
        insert(&mut values, value, policy)?;
    }
    Ok(values)
}

fn finish_object(
    mut object: ExtractedObject,
    policy: Policy,
    manual: Option<&ManualMetadata>,
    publication_date: Option<&[u8]>,
) -> Result<ExtractedObject, Error> {
    if object.directory {
        let mut values = Vec::new();
        for item in decoded(&object.metadata, policy)?.items() {
            if item.kind == 1 {
                continue;
            }
            insert(&mut values, owned(item)?, policy)?;
        }
        insert(&mut values, owned(gnunet_fs::directory::MIME_ITEM)?, policy)?;
        let keyword = gnunet_fs::directory::MIME;
        if policy.extract && !object.keywords.iter().any(|entry| entry == keyword) {
            if object.keywords.len() >= policy.max_keywords {
                return Err(Error::Limit);
            }
            object.keywords.try_reserve(1).map_err(|_| Error::Limit)?;
            object.keywords.push(copy(keyword)?);
        }
        object.metadata = encode_values(&values, policy)?;
    }
    if let Some(manual) = manual {
        object.metadata = manual.merge_wire(&object.metadata, policy)?;
    }
    if let Some(date) = publication_date {
        if date.contains(&0) || date.len() >= policy.max_metadata_bytes {
            return Err(Error::Limit);
        }
        let mut values = Vec::new();
        for item in decoded(&object.metadata, policy)?
            .items()
            .filter(|item| item.kind != 24)
        {
            insert(&mut values, owned(item)?, policy)?;
        }
        let mut data = copy(date)?;
        data.try_reserve(1).map_err(|_| Error::Limit)?;
        data.push(0);
        insert(
            &mut values,
            owned(md::Item {
                kind: 24,
                format: md::Format::Utf8,
                data: &data,
                plugin: Some(b"<gnunet>\0"),
                mime: Some(b"text/plain\0"),
            })?,
            policy,
        )?;
        object.metadata = encode_values(&values, policy)?;
    }
    Ok(object)
}

/// Inspect metadata, retain a bounded tree, apply the official strict-majority
/// share-tree trimming, then deliver the resulting objects in preorder.
#[expect(
    clippy::too_many_arguments,
    reason = "The inspector, preview date and independent event/record outputs are caller-owned"
)]
pub fn inspect_trimmed(
    input: &Path,
    limits: Limits,
    mut policy: Policy,
    metadata: MetadataSettings,
    publication_date: Option<&[u8]>,
    mut control: impl FnMut(Progress) -> Control,
    mut visit: impl FnMut(ExtractedObject) -> Result<(), Error>,
    observe: impl FnMut(InspectionEvent<'_>) -> Result<(), Error>,
) -> Result<InspectionReport, Box<InspectionFailure>> {
    let manual = metadata.manual();
    let settings = metadata.retained_bytes().map_err(|cause| {
        Box::new(InspectionFailure {
            report: InspectionReport::default(),
            cause,
        })
    })?;
    let mut tree = Tree {
        nodes: Vec::new(),
        parents: Vec::new(),
        budget: Budget {
            used: settings,
            limit: policy.max_retained_bytes,
        },
    };
    policy.extract &= metadata.automatic_keywords_enabled();
    policy.creation_time = None;
    let report = inspect_observed(
        input,
        limits,
        policy,
        metadata.with_manual(ManualMetadata::default()),
        &mut control,
        |object| tree.push(object),
        observe,
    )?;
    policy.max_metadata_items = limits.metadata.max_entries.min(256);
    let user = std::env::var_os("USER");
    let user_bytes = user.as_deref().map(gnunet_native::os_bytes::encode);
    (|| -> Result<(), Error> {
        tree.trim(policy, user_bytes.as_deref(), &mut control)?;
        for node in tree.nodes {
            if control(Progress::default()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            let manual = node
                .object
                .relative
                .as_os_str()
                .is_empty()
                .then_some(manual.as_deref())
                .flatten();
            visit(finish_object(
                node.object,
                policy,
                manual,
                publication_date,
            )?)?;
        }
        Ok(())
    })()
    .map_err(|cause| Box::new(InspectionFailure { report, cause }))?;
    Ok(report)
}
