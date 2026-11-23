//! Namespace-aware projection of XMP packets into the GNU metadata registry.

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use quick_xml::{
    XmlVersion,
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
    name::{LocalName, Namespace, NamespaceResolver, ResolveResult},
    reader::NsReader,
};

const MAX_DEPTH: usize = 64;
pub(super) const UUID: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];
const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const META: &str = "adobe:ns:meta/";
const XML: &str = "http://www.w3.org/XML/1998/namespace";
const PS: &str = "http://ns.adobe.com/photoshop/1.0/";
const XMP: &str = "http://ns.adobe.com/xap/1.0/";
const NOTE: &str = "http://ns.adobe.com/xmp/note/";
const IPTC: &str = "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/";
const MICROSOFT: &str = "http://ns.microsoft.com/photo/1.0/";
const LIGHTROOM: &str = "http://ns.adobe.com/lightroom/1.0/";

#[derive(Clone, Copy)]
enum Field {
    Country,
    City,
    Rating,
    MicrosoftRating,
    CountryCode,
    CreatorTool,
    Subject,
    Extension,
}

// The order is the GNU exiv2 extractor's XMP projection.
const METADATA_KINDS: [u32; 7] = [43, 41, 175, 175, 44, 56, 52];

#[derive(Default)]
pub(super) struct Profile {
    fields: [Option<String>; METADATA_KINDS.len()],
    extension: Option<[u8; 16]>,
}

impl Profile {
    pub(super) fn parse(bytes: &[u8], max_text_bytes: usize) -> Option<Self> {
        let xml = decode_packet(bytes)?;
        let mut reader = NsReader::from_str(&xml);
        reader.config_mut().check_comments = true;
        reader.config_mut().expand_empty_elements = true;
        let mut stack = Vec::<Frame>::new();
        let mut profile = Self::default();
        let mut had_root = false;
        let mut had_graph = false;
        let mut had_declaration = false;
        let limit = max_text_bytes.max(32);

        loop {
            match reader.read_event().ok()? {
                Event::Start(start) => {
                    if stack.len() == MAX_DEPTH || (stack.is_empty() && had_root) {
                        return None;
                    }
                    had_root = true;
                    let resolver = reader.resolver();
                    let (namespace, local) = resolver.resolve_element(start.name());
                    let name = name(namespace, local)?;
                    let mut frame = Frame::start(stack.last_mut(), name);
                    had_graph |= matches!(frame, Frame::Graph);
                    frame.attributes(start, resolver, &mut profile, limit, max_text_bytes)?;
                    stack.push(frame);
                }
                Event::End(_) => {
                    stack
                        .pop()?
                        .close(stack.last_mut(), &mut profile, limit, max_text_bytes);
                }
                Event::Text(event) => {
                    let text = event.xml10_content();
                    if let Some(frame) = stack.last_mut() {
                        frame.text(&text, limit);
                    } else if !text.as_bytes().iter().copied().all(xml_space) {
                        return None;
                    }
                }
                Event::CData(event) => stack.last_mut()?.text(&event.xml10_content(), limit),
                Event::GeneralRef(event) => {
                    let frame = stack.last_mut()?;
                    if let Some(character) = event.resolve_char_ref().ok()? {
                        if !xml_char(character) {
                            return None;
                        }
                        frame.text(character.encode_utf8(&mut [0; 4]), limit);
                    } else {
                        frame.text(resolve_predefined_entity(event.as_ref())?, limit);
                    }
                }
                Event::Decl(event) => {
                    if had_root || had_declaration || event.version().ok()?.as_ref() != "1.0" {
                        return None;
                    }
                    had_declaration = true;
                }
                Event::Comment(_) | Event::PI(_) => {}
                Event::DocType(_) | Event::Empty(_) => return None,
                Event::Eof => return (had_graph && stack.is_empty()).then_some(profile),
            }
        }
    }

    pub(super) fn emit<E>(
        &self,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for (kind, value) in METADATA_KINDS.into_iter().zip(&self.fields) {
            if let Some(value) = value {
                emit(kind, value.as_bytes())?;
            }
        }
        Ok(())
    }

    pub(super) const fn extended_id(&self) -> Option<[u8; 16]> {
        self.extension
    }

    pub(super) fn merge(&mut self, extension: Self) {
        for (standard, extended) in self.fields.iter_mut().zip(extension.fields) {
            if standard.is_none() {
                *standard = extended;
            }
        }
    }

    fn record(&mut self, field: Field, value: Value, max_text_bytes: usize) {
        let Value::Text(mut value) = value else {
            return;
        };
        if matches!(field, Field::Extension) {
            if self.extension.is_none() {
                self.extension = parse_guid(value.trim_ascii().as_bytes());
            }
            return;
        }
        let start = value.len() - value.trim_ascii_start().len();
        if start == value.len() || value.len() - start > max_text_bytes {
            return;
        }
        // Keep the first complete value, as in the RDF graph property lookup.
        let slot = &mut self.fields[field as usize];
        if slot.is_none() {
            value.drain(..start);
            *slot = Some(value);
        }
    }
}

pub(super) fn visit<E>(
    bytes: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(profile) = Profile::parse(bytes, limit) else {
        return Ok(false);
    };
    profile.emit(emit)?;
    Ok(true)
}

pub(super) fn parse_guid(bytes: &[u8]) -> Option<[u8; 16]> {
    let bytes: &[u8; 32] = bytes.try_into().ok()?;
    let mut id = [0; 16];
    for (output, [hi, lo]) in id.iter_mut().zip(bytes.as_chunks::<2>().0.iter().copied()) {
        *output = (hex_digit(hi)? << 4) | hex_digit(lo)?;
    }
    Some(id)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

enum Name {
    Meta,
    Graph,
    Description,
    Ordered,
    Alternative,
    Item,
    QualifiedValue,
    Resource,
    Language,
    Field(Field),
    Other,
}

fn name(namespace: ResolveResult<'_>, local: LocalName<'_>) -> Option<Name> {
    let namespace = match namespace {
        ResolveResult::Bound(Namespace(bytes)) => bytes,
        ResolveResult::Unbound => return Some(Name::Other),
        ResolveResult::Unknown(_) => return None,
    };
    Some(match (namespace, local.as_ref()) {
        (META, "xmpmeta" | "xapmeta") => Name::Meta,
        (RDF, "RDF") => Name::Graph,
        (RDF, "Description") => Name::Description,
        (RDF, "Bag" | "Seq") => Name::Ordered,
        (RDF, "Alt") => Name::Alternative,
        (RDF, "li") => Name::Item,
        (RDF, "value") => Name::QualifiedValue,
        (RDF, "resource") => Name::Resource,
        (XML, "lang") => Name::Language,
        (PS, "Country") => Name::Field(Field::Country),
        (PS, "City") => Name::Field(Field::City),
        (XMP, "Rating") => Name::Field(Field::Rating),
        (MICROSOFT, "Rating") => Name::Field(Field::MicrosoftRating),
        (IPTC, "CountryCode") => Name::Field(Field::CountryCode),
        (XMP, "CreatorTool") => Name::Field(Field::CreatorTool),
        (LIGHTROOM, "hierarchicalSubject") => Name::Field(Field::Subject),
        (NOTE, "HasExtendedXMP") => Name::Field(Field::Extension),
        _ => Name::Other,
    })
}

enum Frame {
    Meta,
    Graph,
    Subject,
    Property(Field, Property),
    Item { preferred: bool, property: Property },
    Array(Array),
    Qualifier(Option<Value>),
    QualifiedValue(Property),
    Ignore,
}

impl Frame {
    fn start(parent: Option<&mut Self>, name: Name) -> Self {
        match (parent, name) {
            (None, Name::Meta) => Self::Meta,
            (None | Some(Self::Meta), Name::Graph) => Self::Graph,
            (Some(Self::Graph), Name::Description) => Self::Subject,
            (Some(Self::Subject), Name::Field(field)) => Self::Property(field, Property::default()),
            (Some(Self::Property(_, property) | Self::QualifiedValue(property)), Name::Ordered) => {
                property.has_child = true;
                Self::Array(Array::Items(Text::default()))
            }
            (
                Some(Self::Property(_, property) | Self::QualifiedValue(property)),
                Name::Alternative,
            ) => {
                property.has_child = true;
                Self::Array(Array::Alternative {
                    first: None,
                    preferred: None,
                })
            }
            (Some(Self::Array(_)), Name::Item) => Self::Item {
                preferred: false,
                property: Property::default(),
            },
            (
                Some(Self::Property(_, property) | Self::Item { property, .. }),
                Name::Description,
            ) => {
                property.has_child = true;
                Self::Qualifier(None)
            }
            (
                Some(Self::Property(_, property) | Self::Item { property, .. }),
                Name::QualifiedValue,
            ) => {
                property.has_child = true;
                Self::QualifiedValue(Property::default())
            }
            (Some(Self::Qualifier(_)), Name::QualifiedValue) => {
                Self::QualifiedValue(Property::default())
            }
            (
                Some(
                    Self::Property(_, property)
                    | Self::Item { property, .. }
                    | Self::QualifiedValue(property),
                ),
                _,
            ) => {
                property.has_child = true;
                Self::Ignore
            }
            _ => Self::Ignore,
        }
    }

    fn attributes(
        &mut self,
        start: BytesStart<'_>,
        resolver: &NamespaceResolver,
        profile: &mut Profile,
        limit: usize,
        max_text_bytes: usize,
    ) -> Option<()> {
        for attribute in start.attributes() {
            let attribute = attribute.ok()?;
            let value = attribute.normalized_value(XmlVersion::Implicit1_0).ok()?;
            if !value.chars().all(xml_char) {
                return None;
            }
            // Namespace declarations were already applied by NsReader.
            if attribute.key.as_ref() == "xmlns" || attribute.key.as_ref().starts_with("xmlns:") {
                continue;
            }
            let (namespace, local) = resolver.resolve_attribute(attribute.key);
            match (&mut *self, name(namespace, local)?) {
                (Self::Subject, Name::Field(field)) => {
                    profile.record(field, Value::from_text(&value, limit), max_text_bytes);
                }
                (Self::Item { preferred, .. }, Name::Language) => {
                    *preferred = value.eq_ignore_ascii_case("x-default");
                }
                (
                    Self::Property(_, property)
                    | Self::Item { property, .. }
                    | Self::QualifiedValue(property),
                    Name::Resource,
                ) => property.text.push(&value, limit),
                (Self::Qualifier(nested), Name::QualifiedValue) => {
                    *nested = Some(Value::from_text(&value, limit));
                }
                _ => {}
            }
        }
        Some(())
    }

    fn text(&mut self, text: &str, limit: usize) {
        match self {
            Self::Property(_, property)
            | Self::Item { property, .. }
            | Self::QualifiedValue(property) => {
                property.text.push(text, limit);
            }
            _ => {}
        }
    }

    fn close(
        self,
        parent: Option<&mut Self>,
        profile: &mut Profile,
        limit: usize,
        max_text_bytes: usize,
    ) {
        match (self, parent) {
            (Self::Property(field, value), _) => {
                profile.record(field, value.finish(), max_text_bytes);
            }
            (
                Self::Item {
                    preferred,
                    property,
                },
                Some(Self::Array(array)),
            ) => {
                array.push(property.finish(), preferred, limit);
            }
            (
                Self::Array(values),
                Some(Self::Property(_, parent) | Self::QualifiedValue(parent)),
            ) => {
                parent.value.get_or_insert_with(|| values.finish());
            }
            (
                Self::Qualifier(Some(value)),
                Some(
                    Self::Property(_, parent)
                    | Self::Item {
                        property: parent, ..
                    },
                ),
            ) => {
                parent.value.get_or_insert(value);
            }
            (
                Self::QualifiedValue(value),
                Some(
                    Self::Property(_, parent)
                    | Self::Item {
                        property: parent, ..
                    },
                ),
            ) => {
                parent.value.get_or_insert_with(|| value.finish());
            }
            (Self::QualifiedValue(value), Some(Self::Qualifier(parent))) => {
                parent.get_or_insert_with(|| value.finish());
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Property {
    text: Text,
    has_child: bool,
    value: Option<Value>,
}

impl Property {
    fn finish(self) -> Value {
        if self.has_child {
            self.value.unwrap_or(Value::Empty)
        } else {
            self.text.finish()
        }
    }
}

#[derive(Default)]
struct Text {
    bytes: String,
    oversized: bool,
}

impl Text {
    fn push(&mut self, bytes: &str, limit: usize) {
        if self.oversized {
            return;
        }
        if bytes.len() > limit.saturating_sub(self.bytes.len())
            || self.bytes.try_reserve(bytes.len()).is_err()
        {
            self.bytes.clear();
            self.oversized = true;
        } else {
            self.bytes.push_str(bytes);
        }
    }

    fn finish(self) -> Value {
        if self.oversized {
            Value::Oversized
        } else if self.bytes.is_empty() {
            Value::Empty
        } else {
            Value::Text(self.bytes)
        }
    }
}

enum Value {
    Empty,
    Text(String),
    Oversized,
}

impl Value {
    fn from_text(value: &str, limit: usize) -> Self {
        let mut text = Text::default();
        text.push(value, limit);
        text.finish()
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Text(text) => text.trim_ascii().is_empty(),
            Self::Oversized => false,
        }
    }
}

enum Array {
    Items(Text),
    Alternative {
        first: Option<Value>,
        preferred: Option<Value>,
    },
}

impl Array {
    fn push(&mut self, value: Value, preferred_language: bool, limit: usize) {
        match self {
            Self::Items(text) => match value {
                Value::Empty => {}
                Value::Oversized => text.oversized = true,
                Value::Text(item) => {
                    if !text.bytes.is_empty() {
                        text.push(", ", limit);
                    }
                    text.push(&item, limit);
                }
            },
            Self::Alternative { first, preferred } if !value.is_empty() => {
                if preferred_language {
                    preferred.get_or_insert(value);
                } else {
                    first.get_or_insert(value);
                }
            }
            Self::Alternative { .. } => {}
        }
    }

    fn finish(self) -> Value {
        match self {
            Self::Items(text) => text.finish(),
            Self::Alternative { first, preferred } => preferred.or(first).unwrap_or(Value::Empty),
        }
    }
}

fn xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\r' | b'\n' | b'\t')
}

fn xml_char(character: char) -> bool {
    matches!(character, '\t' | '\r' | '\n' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn decode_packet(bytes: &[u8]) -> Option<Cow<'_, str>> {
    let xml = match bytes {
        [0x00, 0x00, 0xfe, 0xff, rest @ ..] => Cow::Owned(utf32(rest, u32::from_be_bytes)?),
        [0xff, 0xfe, 0x00, 0x00, rest @ ..] => Cow::Owned(utf32(rest, u32::from_le_bytes)?),
        [0x00, 0x00, 0x00, b'<', ..] => Cow::Owned(utf32(bytes, u32::from_be_bytes)?),
        [b'<', 0x00, 0x00, 0x00, ..] => Cow::Owned(utf32(bytes, u32::from_le_bytes)?),
        [0xfe, 0xff, rest @ ..] => Cow::Owned(utf16(rest, u16::from_be_bytes)?),
        [0xff, 0xfe, rest @ ..] => Cow::Owned(utf16(rest, u16::from_le_bytes)?),
        [0x00, b'<', 0x00, _, ..] => Cow::Owned(utf16(bytes, u16::from_be_bytes)?),
        [b'<', 0x00, _, 0x00, ..] => Cow::Owned(utf16(bytes, u16::from_le_bytes)?),
        [0xef, 0xbb, 0xbf, rest @ ..] => Cow::Borrowed(std::str::from_utf8(rest).ok()?),
        _ => Cow::Borrowed(std::str::from_utf8(bytes).ok()?),
    };
    xml.chars().all(xml_char).then_some(xml)
}

fn utf16(bytes: &[u8], decode: fn([u8; 2]) -> u16) -> Option<String> {
    let (words, trailing) = bytes.as_chunks::<2>();
    if !trailing.is_empty() {
        return None;
    }
    char::decode_utf16(words.iter().copied().map(decode))
        .collect::<Result<String, _>>()
        .ok()
}

fn utf32(bytes: &[u8], decode: fn([u8; 4]) -> u32) -> Option<String> {
    let (words, trailing) = bytes.as_chunks::<4>();
    if !trailing.is_empty() {
        return None;
    }
    words
        .iter()
        .copied()
        .map(decode)
        .map(char::from_u32)
        .collect()
}
