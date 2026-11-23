//! Positioned PDF document structure under the publication probe.

use std::borrow::Cow;

use super::super::Input;
use super::filespec::{self, Strings};
use super::parameters::{Access, Origin, ParameterCache, ParameterError, Parameters, Resolved};
use super::security::{
    Dictionary as EncryptionDictionary, ObjectEncryption, Security, StreamPurpose,
};
use super::stream::{Expansion, Pipeline};
use super::syntax::{Cursor, Dict, ObjectId, ParseError, Value};
use super::xref::{
    Entry, ObjectStream, ObjectStreamIndex, TablePart, TableRows, XrefStream, parse_table_entry,
    parse_table_part, parse_table_start,
};

const TAIL_BYTES: usize = 1024;
const START_WINDOW: usize = 64;
const MAX_EXPANDED_BYTES: usize = 1 << 20;
const MAX_REVISIONS: usize = 64;
const MAX_SUBSECTIONS: usize = 1024;
const MAX_FILE_ID_BYTES: usize = 4096;

type Parsed<T> = Result<T, ParseError>;

pub(super) struct Opened<D, T> {
    pub(super) document: D,
    pub(super) info: Option<Info<T>>,
}

pub(super) struct Document<'a, Read> {
    probe: Probe<'a, Read>,
    revisions: Vec<Revision>,
    object_streams: Vec<(u32, Option<ObjectStream>)>,
    parameters: ParameterCache,
    root: ObjectId,
    size: u64,
    expansion: Expansion,
    security: Option<Security>,
}

impl<'a, E, Read: FnMut(u64, &mut [u8]) -> Result<(), E>> Document<'a, Read> {
    pub(super) fn open<T>(
        input: Input<'a, Read>,
        project_info: &impl Fn(Dict<'_>) -> T,
    ) -> Result<Option<Opened<Self, T>>, E> {
        let probe_bytes = input.prefix.len().saturating_add(input.unread_bytes());
        let mut expansion = Expansion::new(probe_bytes.saturating_mul(4).min(MAX_EXPANDED_BYTES));
        let mut probe = Probe::new(input)?;
        let Some(mut offset) = startxref(&probe.tail.bytes).filter(|at| *at < probe.input.extent)
        else {
            return Ok(None);
        };
        let mut revisions = Vec::<Revision>::new();
        let mut root = None;
        let mut info = None;
        let mut size = None;
        let mut encryption = None;
        let mut file_id = None;
        let mut subsections_left = MAX_SUBSECTIONS;
        loop {
            if revisions.len() == MAX_REVISIONS || revisions.iter().any(|rev| rev.offset == offset)
            {
                return Ok(None);
            }
            let Some((xref, trailer)) = read_section(
                &mut probe,
                offset,
                &mut expansion,
                &mut subsections_left,
                project_info,
            )?
            else {
                return Ok(None);
            };
            root = root.or(trailer.root);
            info = info.or(trailer.info);
            encryption = encryption.or(trailer.encryption);
            file_id = file_id.or(trailer.file_id);
            size.get_or_insert(trailer.size);
            revisions.push(Revision { offset, xref });
            let Some(prev) = trailer.prev else { break };
            offset = prev;
        }
        let Some((root, size)) = root.flatten().zip(size) else {
            return Ok(None);
        };
        let security = if let Some(encryption) = encryption {
            let Some(dictionary) = encryption.read(&mut probe, &revisions, size)? else {
                return Ok(None);
            };
            let Some(security) = dictionary.unlock(file_id.as_deref(), probe.input.pdf_recipient)
            else {
                return Ok(None);
            };
            Some(security)
        } else {
            None
        };
        Ok(Some(Opened {
            document: Self {
                probe,
                revisions,
                object_streams: Vec::new(),
                parameters: ParameterCache::new(probe_bytes),
                root,
                size,
                expansion,
                security,
            },
            info: info.flatten(),
        }))
    }

    pub(super) fn root(&self) -> ObjectId {
        self.root
    }

    pub(super) fn value<T>(
        &mut self,
        id: ObjectId,
        project: impl Fn(Value<'_>, ObjectEncryption<'_>) -> Option<T>,
    ) -> Result<Option<T>, E> {
        match self.entry(id.number)? {
            Some(Entry::Direct { offset, generation }) if generation == id.generation => {
                let encryption = ObjectEncryption::for_object(self.security.as_ref(), id);
                self.probe.parse_at(offset, |bytes| {
                    let object = direct_object(bytes, id)?;
                    project(object.value, encryption).ok_or(ParseError::Invalid)
                })
            }
            Some(Entry::Compressed { stream, index }) if id.generation == 0 => Ok(self
                .compressed_object(id.number, stream, index)?
                .and_then(|bytes| {
                    project(
                        Cursor::complete(bytes).one_value().ok()?,
                        ObjectEncryption::Plain,
                    )
                })),
            _ => Ok(None),
        }
    }

    fn compressed_object(
        &mut self,
        number: u32,
        stream: u32,
        index: u32,
    ) -> Result<Option<&[u8]>, E> {
        let cached = match self.object_streams.iter().position(|(id, _)| *id == stream) {
            Some(index) => index,
            None => {
                let decoded = self.object_stream(stream)?;
                self.object_streams.push((stream, decoded));
                self.object_streams.len() - 1
            }
        };
        Ok(self.object_streams[cached]
            .1
            .as_ref()
            .and_then(|stream| stream.object(number, index)))
    }

    fn object_stream(&mut self, number: u32) -> Result<Option<ObjectStream>, E> {
        self.read_stream::<ObjectStreamIndex>(
            ObjectId {
                number,
                generation: 0,
            },
            Access::Uncompressed,
        )
    }

    pub(super) fn metadata_stream(&mut self, id: ObjectId) -> Result<Option<Vec<u8>>, E> {
        self.read_stream::<XmlMetadata>(id, Access::Document)
    }

    fn read_stream<K: StreamContents>(
        &mut self,
        id: ObjectId,
        access: Access,
    ) -> Result<Option<K::Decoded>, E> {
        let Some(stream) = self.load_stream::<K>(id, access)? else {
            return Ok(None);
        };
        match stream {
            LoadedStream::Inline(bytes) => Ok(Some(bytes)),
            LoadedStream::File {
                source,
                contents,
                pipeline,
            } => {
                let bytes = match source {
                    filespec::Source::Embedded(id) => {
                        let Some(LoadedStream::Inline(bytes)) =
                            self.load_stream::<EmbeddedFile>(id, access)?
                        else {
                            return Ok(None);
                        };
                        Cow::Owned(bytes)
                    }
                    filespec::Source::External { kind, name } => {
                        let Some(bytes) = self
                            .probe
                            .input
                            .pdf_streams
                            .and_then(|bindings| bindings.find(kind, &name))
                        else {
                            return Ok(None);
                        };
                        if self.probe.input.charge_unread(bytes.len()).is_none() {
                            return Ok(None);
                        }
                        Cow::Borrowed(bytes)
                    }
                };
                Ok(contents.decode(&pipeline, &bytes, &mut self.expansion))
            }
        }
    }

    fn load_stream<K: StreamContents>(
        &mut self,
        id: ObjectId,
        access: Access,
    ) -> Result<Option<LoadedStream<K>>, E> {
        let Some(Entry::Direct { offset, generation }) = self.entry(id.number)? else {
            return Ok(None);
        };
        if generation != id.generation {
            return Ok(None);
        }
        let expansion = &mut self.expansion;
        let parameters = self.parameters.scoped(access);
        let encryption = ObjectEncryption::for_object(self.security.as_ref(), id);
        let strings = Strings::new(self.security.as_ref(), id);
        let allow_external = self.probe.input.pdf_streams.is_some();
        let Some(stream) = self.probe.parse_at(offset, |bytes| {
            let (actual, dict, body) = stream_header(bytes)?;
            if actual != id {
                return Err(ParseError::Invalid);
            }
            match StreamHeader::<K>::parse(dict, &parameters, strings, allow_external) {
                Ok(header) => {
                    let payload = stream_payload(body, header.length)?;
                    header
                        .decode(payload, encryption, expansion)
                        .map(StreamRead::Complete)
                }
                Err(ParameterError::Missing(first)) => {
                    let prefix_len = bytes.len() - body.len();
                    let body_at = offset
                        .checked_add(prefix_len as u64)
                        .ok_or(ParseError::Invalid)?;
                    Ok(StreamRead::Deferred {
                        prefix: bytes[..prefix_len].into(),
                        body_at,
                        first,
                    })
                }
                Err(ParameterError::Invalid) => Err(ParseError::Invalid),
            }
        })?
        else {
            return Ok(None);
        };
        let (prefix, body_at, mut needed) = match stream {
            StreamRead::Complete(stream) => return Ok(Some(stream)),
            StreamRead::Deferred {
                prefix,
                body_at,
                first,
            } => (prefix, body_at, first),
        };
        let Ok((_, dict, _)) = stream_header(&prefix) else {
            return Ok(None);
        };
        let header = loop {
            if !self.read_parameter(needed, access)? {
                return Ok(None);
            }
            let strings = Strings::new(self.security.as_ref(), id);
            match StreamHeader::<K>::parse(
                dict,
                &self.parameters.scoped(access),
                strings,
                allow_external,
            ) {
                Ok(header) => break header,
                Err(ParameterError::Missing(id)) => needed = id,
                Err(ParameterError::Invalid) => return Ok(None),
            }
        };
        let expansion = &mut self.expansion;
        let encryption = ObjectEncryption::for_object(self.security.as_ref(), id);
        let length = header.length;
        let mut header = Some(header);
        self.probe.parse_at(body_at, |body| {
            let payload = stream_payload(body, length)?;
            header
                .take()
                .ok_or(ParseError::Invalid)?
                .decode(payload, encryption, expansion)
        })
    }

    fn read_parameter(&mut self, id: ObjectId, access: Access) -> Result<bool, E> {
        let (origin, bytes) = match self.entry(id.number)? {
            Some(Entry::Direct { offset, generation }) if generation == id.generation => (
                Origin::Uncompressed,
                self.probe.parse_at(offset, |bytes| {
                    let object = direct_object(bytes, id)?;
                    Ok(Box::<[u8]>::from(object.encoded))
                })?,
            ),
            Some(Entry::Compressed { stream, index })
                if id.generation == 0 && matches!(access, Access::Document) =>
            {
                (
                    Origin::Compressed,
                    self.compressed_object(id.number, stream, index)?
                        .map(Box::<[u8]>::from),
                )
            }
            _ => return Ok(false),
        };
        Ok(bytes
            .and_then(|bytes| self.parameters.insert(id, origin, bytes))
            .is_some())
    }

    fn entry(&mut self, number: u32) -> Result<Option<Entry>, E> {
        lookup_entry(&mut self.probe, &self.revisions, self.size, number)
    }
}

fn lookup_entry<E>(
    probe: &mut Probe<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    revisions: &[Revision],
    size: u64,
    number: u32,
) -> Result<Option<Entry>, E> {
    if number == 0 || u64::from(number) >= size {
        return Ok(None);
    }
    for revision in revisions {
        match &revision.xref {
            Xref::Stream(stream) => {
                if let Some(entry) = stream.entry(number) {
                    return Ok(Some(entry));
                }
            }
            Xref::Table { rows, supplement } => {
                if let Some(offset) = rows.iter().find_map(|rows| rows.row_offset(number)) {
                    // The same-revision table owns every number it lists, including free rows.
                    return probe.parse_at(offset, parse_table_entry);
                }
                if let Some(entry) = supplement.as_ref().and_then(|stream| stream.entry(number)) {
                    return Ok(Some(entry));
                }
            }
        }
    }
    Ok(None)
}

enum StreamRead<K: StreamContents> {
    Complete(LoadedStream<K>),
    Deferred {
        prefix: Box<[u8]>,
        body_at: u64,
        first: ObjectId,
    },
}

enum LoadedStream<K: StreamContents> {
    Inline(K::Decoded),
    File {
        source: filespec::Source,
        contents: K,
        pipeline: Pipeline,
    },
}

enum StreamSource {
    Inline(Pipeline),
    File(filespec::Source, Pipeline),
}

struct StreamHeader<K> {
    length: u64,
    contents: K,
    source: StreamSource,
}

impl<K: StreamContents> StreamHeader<K> {
    fn parse(
        dict: Dict<'_>,
        parameters: &Parameters<'_>,
        strings: Strings<'_>,
        allow_external: bool,
    ) -> Result<Self, ParameterError> {
        match parameters.get(dict, b"Type")? {
            Some(Value::Name(name)) if name.is(K::PDF_TYPE) => {}
            None | Some(Value::Null) if matches!(K::PURPOSE, StreamPurpose::EmbeddedFile) => {}
            _ => return Err(ParameterError::Invalid),
        }
        let length = stream_integer(dict, parameters, b"Length")?;
        let contents = K::parse(dict, parameters)?;
        let source = match parameters.locate(dict, b"F")? {
            None
            | Some(Resolved {
                value: Value::Null, ..
            }) => StreamSource::Inline(Pipeline::parse_inline(dict, parameters)?),
            Some(file) if !matches!(K::PURPOSE, StreamPurpose::EmbeddedFile) => StreamSource::File(
                filespec::parse(file, parameters, strings, allow_external)?,
                Pipeline::parse_external(dict, parameters)?,
            ),
            _ => return Err(ParameterError::Invalid),
        };
        Ok(Self {
            length,
            contents,
            source,
        })
    }

    fn decode(
        self,
        payload: &[u8],
        encryption: ObjectEncryption<'_>,
        expansion: &mut Expansion,
    ) -> Parsed<LoadedStream<K>> {
        match self.source {
            StreamSource::Inline(pipeline) => {
                let payload = encryption
                    .stream(K::PURPOSE, pipeline.crypt_filter(), payload)
                    .ok_or(ParseError::Invalid)?;
                self.contents
                    .decode(&pipeline, &payload, expansion)
                    .map(LoadedStream::Inline)
                    .ok_or(ParseError::Invalid)
            }
            StreamSource::File(source, pipeline) => Ok(LoadedStream::File {
                source,
                contents: self.contents,
                pipeline,
            }),
        }
    }
}

fn stream_integer(
    dict: Dict<'_>,
    parameters: &Parameters<'_>,
    key: &[u8],
) -> Result<u64, ParameterError> {
    match parameters.get(dict, key)? {
        Some(Value::Unsigned(value)) => Ok(value),
        _ => Err(ParameterError::Invalid),
    }
}

trait StreamContents: Sized {
    type Decoded;
    const PDF_TYPE: &[u8];
    const PURPOSE: StreamPurpose;

    fn parse(dict: Dict<'_>, parameters: &Parameters<'_>) -> Result<Self, ParameterError>;
    fn decode(
        &self,
        pipeline: &Pipeline,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self::Decoded>;
}

impl StreamContents for ObjectStreamIndex {
    type Decoded = ObjectStream;
    const PDF_TYPE: &[u8] = b"ObjStm";
    const PURPOSE: StreamPurpose = StreamPurpose::Objects;

    fn parse(dict: Dict<'_>, parameters: &Parameters<'_>) -> Result<Self, ParameterError> {
        Self::new(
            stream_integer(dict, parameters, b"First")?,
            stream_integer(dict, parameters, b"N")?,
        )
        .ok_or(ParameterError::Invalid)
    }

    fn decode(
        &self,
        pipeline: &Pipeline,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self::Decoded> {
        ObjectStream::decode(*self, pipeline, payload, expansion)
    }
}

struct XmlMetadata;

impl StreamContents for XmlMetadata {
    type Decoded = Vec<u8>;
    const PDF_TYPE: &[u8] = b"Metadata";
    const PURPOSE: StreamPurpose = StreamPurpose::Metadata;

    fn parse(dict: Dict<'_>, parameters: &Parameters<'_>) -> Result<Self, ParameterError> {
        match parameters.get(dict, b"Subtype")? {
            Some(Value::Name(name)) if name.is(b"XML") => Ok(Self),
            _ => Err(ParameterError::Invalid),
        }
    }

    fn decode(
        &self,
        pipeline: &Pipeline,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self::Decoded> {
        Some(
            expansion
                .decode_pipeline(pipeline, payload, None)?
                .into_owned(),
        )
    }
}

struct EmbeddedFile;

impl StreamContents for EmbeddedFile {
    type Decoded = Vec<u8>;
    const PDF_TYPE: &[u8] = b"EmbeddedFile";
    const PURPOSE: StreamPurpose = StreamPurpose::EmbeddedFile;

    fn parse(_dict: Dict<'_>, _parameters: &Parameters<'_>) -> Result<Self, ParameterError> {
        Ok(Self)
    }

    fn decode(
        &self,
        pipeline: &Pipeline,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self::Decoded> {
        Some(
            expansion
                .decode_pipeline(pipeline, payload, None)?
                .into_owned(),
        )
    }
}

struct Revision {
    offset: u64,
    xref: Xref,
}

enum Xref {
    Table {
        rows: Vec<PositionedRows>,
        supplement: Option<XrefStream>,
    },
    Stream(XrefStream),
}

struct PositionedRows {
    offset: u64,
    rows: TableRows,
}

impl PositionedRows {
    fn row_offset(&self, number: u32) -> Option<u64> {
        self.offset.checked_add(self.rows.row_offset(number)?)
    }
}

pub(super) enum Info<T> {
    Direct(T),
    Reference(ObjectId),
}

struct Trailer<T> {
    root: Option<Option<ObjectId>>,
    info: Option<Option<Info<T>>>,
    size: u64,
    encryption: Option<Encryption>,
    file_id: Option<Box<[u8]>>,
    prev: Option<u64>,
    supplement: Option<u64>,
}

impl<T> Trailer<T> {
    fn parse(dict: Dict<'_>, project_info: &impl Fn(Dict<'_>) -> T) -> Parsed<Self> {
        let info = match dict.unique(b"Info")? {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::Dict(dict)) => Some(Some(Info::Direct(project_info(dict)))),
            Some(Value::Reference(id)) if id.number != 0 => Some(Some(Info::Reference(id))),
            _ => return Err(ParseError::Invalid),
        };
        let Some(Value::Unsigned(size)) = dict.unique(b"Size")? else {
            return Err(ParseError::Invalid);
        };
        if !(1..=u64::from(u32::MAX) + 1).contains(&size) {
            return Err(ParseError::Invalid);
        }
        Ok(Self {
            root: reference_key(dict, b"Root")?,
            info,
            size,
            encryption: Encryption::parse(dict.unique(b"Encrypt")?)?,
            file_id: file_identifier(dict.unique(b"ID")?),
            prev: offset_key(dict, b"Prev")?,
            supplement: offset_key(dict, b"XRefStm")?,
        })
    }
}

enum Encryption {
    Direct(Box<EncryptionDictionary>),
    Reference(ObjectId),
}

impl Encryption {
    fn parse(value: Option<Value<'_>>) -> Parsed<Option<Self>> {
        match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Reference(id)) if id.number != 0 => Ok(Some(Self::Reference(id))),
            Some(Value::Dict(dict)) => EncryptionDictionary::parse(dict)
                .map(|dictionary| Some(Self::Direct(Box::new(dictionary))))
                .ok_or(ParseError::Invalid),
            _ => Err(ParseError::Invalid),
        }
    }

    fn read<E>(
        self,
        probe: &mut Probe<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        revisions: &[Revision],
        size: u64,
    ) -> Result<Option<EncryptionDictionary>, E> {
        let id = match self {
            Self::Direct(dictionary) => return Ok(Some(*dictionary)),
            Self::Reference(id) => id,
        };
        let Some(Entry::Direct { offset, generation }) =
            lookup_entry(probe, revisions, size, id.number)?
        else {
            return Ok(None);
        };
        if generation != id.generation {
            return Ok(None);
        }
        probe.parse_at(offset, |bytes| {
            let Value::Dict(dict) = direct_object(bytes, id)?.value else {
                return Err(ParseError::Invalid);
            };
            EncryptionDictionary::parse(dict).ok_or(ParseError::Invalid)
        })
    }
}

fn file_identifier(value: Option<Value<'_>>) -> Option<Box<[u8]>> {
    let Value::Array(array) = value? else {
        return None;
    };
    let Value::String(first) = array.values().next()? else {
        return None;
    };
    Some(
        first
            .bytes(MAX_FILE_ID_BYTES)?
            .into_owned()
            .into_boxed_slice(),
    )
}

fn reference_key(dict: Dict<'_>, key: &[u8]) -> Parsed<Option<Option<ObjectId>>> {
    match dict.unique(key)? {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::Reference(id)) if id.number != 0 => Ok(Some(Some(id))),
        _ => Err(ParseError::Invalid),
    }
}

fn offset_key(dict: Dict<'_>, key: &[u8]) -> Parsed<Option<u64>> {
    match dict.unique(key)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Unsigned(offset)) if offset != 0 => Ok(Some(offset)),
        _ => Err(ParseError::Invalid),
    }
}

enum TableItem<T> {
    Rows(TableRows),
    Trailer(Trailer<T>),
}

fn read_section<E, T>(
    probe: &mut Probe<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    offset: u64,
    expansion: &mut Expansion,
    subsections_left: &mut usize,
    project_info: &impl Fn(Dict<'_>) -> T,
) -> Result<Option<(Xref, Trailer<T>)>, E> {
    let Some(start) = probe.parse_at(offset, |bytes| match parse_table_start(bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(ParseError::Invalid) => Ok(None),
        Err(ParseError::Incomplete) => Err(ParseError::Incomplete),
    })?
    else {
        return Ok(None);
    };
    let Some(start) = start else {
        return Ok(read_xref_stream(probe, offset, expansion, project_info)?
            .map(|(stream, trailer)| (Xref::Stream(stream), trailer)));
    };
    let Some(mut position) = offset.checked_add(start as u64) else {
        return Ok(None);
    };
    let mut rows = Vec::<PositionedRows>::new();
    loop {
        let item = probe.parse_at(position, |bytes| match parse_table_part(bytes)? {
            TablePart::Rows(rows) => Ok(TableItem::Rows(rows)),
            TablePart::Trailer(dict) => Trailer::parse(dict, project_info).map(TableItem::Trailer),
        })?;
        match item {
            Some(TableItem::Rows(part)) if *subsections_left != 0 => {
                let Some(next) = position.checked_add(part.next_offset()) else {
                    return Ok(None);
                };
                let numbers = part.object_numbers();
                let overlaps = rows.iter().any(|prior| {
                    let prior = prior.rows.object_numbers();
                    prior.start < numbers.end && numbers.start < prior.end
                });
                if next <= position || overlaps {
                    return Ok(None);
                }
                rows.push(PositionedRows {
                    offset: position,
                    rows: part,
                });
                position = next;
                *subsections_left -= 1;
            }
            Some(TableItem::Trailer(mut trailer)) if !rows.is_empty() => {
                let supplement = if let Some(offset) = trailer.supplement {
                    let Some((stream, supplement_trailer)) =
                        read_xref_stream(probe, offset, expansion, &|_| ())?
                    else {
                        return Ok(None);
                    };
                    trailer.encryption = trailer.encryption.or(supplement_trailer.encryption);
                    trailer.file_id = trailer.file_id.or(supplement_trailer.file_id);
                    Some(stream)
                } else {
                    None
                };
                return Ok(Some((Xref::Table { rows, supplement }, trailer)));
            }
            _ => return Ok(None),
        }
    }
}

fn read_xref_stream<E, T>(
    probe: &mut Probe<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    offset: u64,
    expansion: &mut Expansion,
    project_info: &impl Fn(Dict<'_>) -> T,
) -> Result<Option<(XrefStream, Trailer<T>)>, E> {
    probe.parse_at(offset, |bytes| {
        let (_, dict, body) = stream_header(bytes)?;
        let Some(Value::Unsigned(length)) = dict.unique(b"Length")? else {
            return Err(ParseError::Invalid);
        };
        let payload = stream_payload(body, length)?;
        let trailer = Trailer::parse(dict, project_info)?;
        let stream = XrefStream::decode(dict, payload, expansion).ok_or(ParseError::Invalid)?;
        Ok((stream, trailer))
    })
}

pub(super) fn named(dict: Dict<'_>, key: &[u8], expected: &[u8]) -> bool {
    matches!(dict.unique(key), Ok(Some(Value::Name(name))) if name.is(expected))
}

fn object_header(cursor: &mut Cursor<'_>) -> Parsed<ObjectId> {
    let number = u32::try_from(cursor.unsigned()?).map_err(|_| ParseError::Invalid)?;
    let generation = u16::try_from(cursor.unsigned()?).map_err(|_| ParseError::Invalid)?;
    cursor.take_keyword(b"obj")?;
    if number == 0 {
        return Err(ParseError::Invalid);
    }
    Ok(ObjectId { number, generation })
}

struct DirectObject<'a> {
    value: Value<'a>,
    encoded: &'a [u8],
}

fn direct_object(bytes: &[u8], expected: ObjectId) -> Parsed<DirectObject<'_>> {
    let mut cursor = Cursor::new(bytes);
    if object_header(&mut cursor)? != expected {
        return Err(ParseError::Invalid);
    }
    let start = cursor.position();
    let value = cursor.value()?;
    let encoded = &bytes[start..cursor.position()];
    cursor.take_keyword(b"endobj")?;
    Ok(DirectObject { value, encoded })
}

fn stream_header(bytes: &[u8]) -> Parsed<(ObjectId, Dict<'_>, &[u8])> {
    let mut cursor = Cursor::new(bytes);
    let id = object_header(&mut cursor)?;
    let Value::Dict(dict) = cursor.value()? else {
        return Err(ParseError::Invalid);
    };
    cursor.take_keyword(b"stream")?;
    let eol = &bytes[cursor.position()..];
    let body = match eol {
        [b'\n', body @ ..] | [b'\r', b'\n', body @ ..] => body,
        [] | [b'\r'] => return Err(ParseError::Incomplete),
        _ => return Err(ParseError::Invalid),
    };
    Ok((id, dict, body))
}

fn stream_payload(body: &[u8], length: u64) -> Parsed<&[u8]> {
    let length = usize::try_from(length).map_err(|_| ParseError::Invalid)?;
    let (data, end) = body
        .split_at_checked(length)
        .ok_or(ParseError::Incomplete)?;
    let mut cursor = Cursor::new(end);
    cursor.take_keyword(b"endstream")?;
    cursor.take_keyword(b"endobj")?;
    Ok(data)
}

struct Window {
    offset: u64,
    bytes: Vec<u8>,
}

impl Window {
    fn from(&self, offset: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset.checked_sub(self.offset)?).ok()?;
        self.bytes.get(start..).filter(|bytes| !bytes.is_empty())
    }

    fn reposition(&mut self, offset: u64) {
        if let Some(bytes) = self.from(offset) {
            let keep = bytes.len();
            let start = self.bytes.len() - keep;
            self.bytes.copy_within(start.., 0);
            self.bytes.truncate(keep);
        } else {
            self.bytes.clear();
        }
        self.offset = offset;
    }
}

struct Probe<'a, Read> {
    input: Input<'a, Read>,
    tail: Window,
    window: Window,
}

impl<'a, E, Read: FnMut(u64, &mut [u8]) -> Result<(), E>> Probe<'a, Read> {
    fn new(mut input: Input<'a, Read>) -> Result<Self, E> {
        let allowance = if input.extent == input.prefix.len() as u64 {
            TAIL_BYTES
        } else {
            input.unread_bytes().div_ceil(4).min(TAIL_BYTES)
        };
        let length = input.extent.min(allowance as u64);
        let offset = input.extent - length;
        let bytes = input
            .range(offset, length as usize)?
            .unwrap_or_default()
            .to_vec();
        Ok(Self {
            input,
            tail: Window { offset, bytes },
            window: Window {
                offset: 0,
                bytes: Vec::new(),
            },
        })
    }

    fn parse_at<T>(
        &mut self,
        offset: u64,
        mut parse: impl FnMut(&[u8]) -> Parsed<T>,
    ) -> Result<Option<T>, E> {
        if offset >= self.input.extent {
            return Ok(None);
        }
        if let Some(bytes) = self.tail.from(offset) {
            return Ok(parse(bytes).ok());
        }
        if let Ok(start) = usize::try_from(offset)
            && let Some(prefix) = self.input.prefix.get(start..)
            && !prefix.is_empty()
        {
            match parse(prefix) {
                Ok(value) => return Ok(Some(value)),
                Err(ParseError::Invalid) => return Ok(None),
                Err(ParseError::Incomplete) => {}
            }
        }
        self.window.reposition(offset);
        loop {
            match parse(&self.window.bytes) {
                Ok(value) => return Ok(Some(value)),
                Err(ParseError::Invalid) => return Ok(None),
                Err(ParseError::Incomplete) => {}
            }
            let buffered = self.window.bytes.len();
            let at = offset + buffered as u64;
            // Grow geometrically while leaving room for other positioned objects.
            let want = (buffered / 2).max(START_WINDOW);
            if at >= self.input.extent {
                return Ok(None);
            }
            if let Ok(start) = usize::try_from(at)
                && let Some(prefix) = self.input.prefix.get(start..)
                && !prefix.is_empty()
            {
                self.window
                    .bytes
                    .extend_from_slice(&prefix[..prefix.len().min(want)]);
            } else if let Some(tail) = self.tail.from(at) {
                self.window
                    .bytes
                    .extend_from_slice(&tail[..tail.len().min(want)]);
            } else {
                let end = if self.tail.bytes.is_empty() {
                    self.input.extent
                } else {
                    self.tail.offset
                };
                let count = (end - at).min(want.min(self.input.unread_bytes()) as u64) as usize;
                if count == 0 {
                    return Ok(None);
                }
                let Some(bytes) = self.input.range(at, count)? else {
                    return Ok(None);
                };
                self.window.bytes.extend_from_slice(bytes);
            }
        }
    }
}

fn startxref(tail: &[u8]) -> Option<u64> {
    let tail = tail.trim_ascii_end().strip_suffix(b"%%EOF")?;
    if !tail.last()?.is_ascii_whitespace() {
        return None;
    }
    let start = tail.windows(9).rposition(|bytes| bytes == b"startxref")?;
    if start > 0 && !matches!(tail[start - 1], b'\r' | b'\n') {
        return None;
    }
    let offset = tail.get(start + 9..)?;
    if !offset.first()?.is_ascii_whitespace() {
        return None;
    }
    let offset = offset.trim_ascii();
    if offset.iter().all(u8::is_ascii_digit) {
        return std::str::from_utf8(offset).ok()?.parse().ok();
    }
    None
}
