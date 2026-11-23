//! Bounded, scoped resolution of indirect stream parameters.

use std::collections::HashMap;

use super::syntax::{Cursor, Dict, ObjectId, ParseError, Value};

const MAX_PARAMETER_OBJECTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParameterError {
    Invalid,
    Missing(ObjectId),
}

impl From<ParseError> for ParameterError {
    fn from(_: ParseError) -> Self {
        Self::Invalid
    }
}

#[derive(Clone, Copy)]
pub(super) enum Access {
    Uncompressed,
    Document,
}

#[derive(Clone, Copy)]
pub(super) enum Origin {
    Uncompressed,
    Compressed,
}

pub(super) struct ParameterCache {
    objects: HashMap<ObjectId, CachedObject>,
    bytes_left: usize,
}

struct CachedObject {
    origin: Origin,
    value: CachedValue,
}

enum CachedValue {
    Reference(ObjectId),
    Literal(Box<[u8]>),
}

pub(super) struct Parameters<'a> {
    indirect: Option<(&'a ParameterCache, Access)>,
}

pub(super) struct Resolved<'a> {
    pub(super) value: Value<'a>,
    pub(super) storage: Option<(ObjectId, Origin)>,
}

impl Parameters<'_> {
    pub(super) const fn direct() -> Self {
        Self { indirect: None }
    }

    pub(super) fn get<'a>(
        &'a self,
        dict: Dict<'a>,
        key: &[u8],
    ) -> Result<Option<Value<'a>>, ParameterError> {
        Ok(self.locate(dict, key)?.map(|entry| entry.value))
    }

    pub(super) fn locate<'a>(
        &'a self,
        dict: Dict<'a>,
        key: &[u8],
    ) -> Result<Option<Resolved<'a>>, ParameterError> {
        let Some(value) = dict.unique(key)? else {
            return Ok(None);
        };
        if self.indirect.is_none() && !is_direct(value) {
            return Err(ParameterError::Invalid);
        }
        self.resolve_located(value).map(Some)
    }

    pub(super) fn resolve<'a>(&'a self, value: Value<'a>) -> Result<Value<'a>, ParameterError> {
        Ok(self.resolve_located(value)?.value)
    }

    fn resolve_located<'a>(&'a self, value: Value<'a>) -> Result<Resolved<'a>, ParameterError> {
        let Value::Reference(mut id) = value else {
            return Ok(Resolved {
                value,
                storage: None,
            });
        };
        let Some((cache, access)) = self.indirect else {
            return Err(ParameterError::Invalid);
        };
        // Every additional link beyond the cached object count repeats an ID.
        for _ in 0..=cache.objects.len() {
            if id.number == 0 {
                return Err(ParameterError::Invalid);
            }
            match cache.objects.get(&id) {
                Some(object) => {
                    if matches!(
                        (access, object.origin),
                        (Access::Uncompressed, Origin::Compressed)
                    ) {
                        return Err(ParameterError::Invalid);
                    }
                    match &object.value {
                        CachedValue::Reference(referent) => id = *referent,
                        CachedValue::Literal(bytes) => {
                            return Ok(Resolved {
                                value: Cursor::complete(bytes).one_value()?,
                                storage: Some((id, object.origin)),
                            });
                        }
                    }
                }
                None if cache.bytes_left != 0 && cache.objects.len() < MAX_PARAMETER_OBJECTS => {
                    return Err(ParameterError::Missing(id));
                }
                None => return Err(ParameterError::Invalid),
            }
        }
        Err(ParameterError::Invalid)
    }
}

impl ParameterCache {
    pub(super) fn new(byte_limit: usize) -> Self {
        Self {
            objects: HashMap::new(),
            bytes_left: byte_limit,
        }
    }

    pub(super) fn scoped(&self, access: Access) -> Parameters<'_> {
        Parameters {
            indirect: Some((self, access)),
        }
    }

    pub(super) fn insert(&mut self, id: ObjectId, origin: Origin, bytes: Box<[u8]>) -> Option<()> {
        if id.number == 0
            || self.objects.len() >= MAX_PARAMETER_OBJECTS
            || self.objects.contains_key(&id)
        {
            return None;
        }
        let remaining = self.bytes_left.checked_sub(bytes.len())?;
        let value = match Cursor::complete(&bytes).one_value().ok()? {
            Value::Reference(referent) => CachedValue::Reference(referent),
            _ => CachedValue::Literal(bytes),
        };
        self.objects.try_reserve(1).ok()?;
        self.objects.insert(id, CachedObject { origin, value });
        self.bytes_left = remaining;
        Some(())
    }
}

fn is_direct(value: Value<'_>) -> bool {
    match value {
        Value::Reference(_) => false,
        Value::Array(array) => array.values().all(is_direct),
        Value::Dict(dict) => dict.entries().all(|(_, value)| is_direct(value)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{Access, ObjectId, Origin, ParameterCache, ParameterError, Value};

    #[test]
    fn cached_parameter_cycles_terminate_and_exhausted_caches_decline_reads() {
        let id = |number| ObjectId {
            number,
            generation: 0,
        };
        let mut objects = ParameterCache::new(10);
        assert!(matches!(
            objects.scoped(Access::Uncompressed).resolve(Value::Reference(id(1))),
            Err(ParameterError::Missing(object)) if object == id(1)
        ));
        assert_eq!(
            objects.insert(id(1), Origin::Uncompressed, Box::from(b"2 0 R".as_slice())),
            Some(())
        );
        assert_eq!(
            objects.insert(id(2), Origin::Uncompressed, Box::from(b"1 0 R".as_slice())),
            Some(())
        );
        for number in [1, 3] {
            assert!(matches!(
                objects
                    .scoped(Access::Uncompressed)
                    .resolve(Value::Reference(id(number))),
                Err(ParameterError::Invalid)
            ));
        }
    }

    #[test]
    fn bootstrap_lookup_rejects_compressed_parameters_already_in_the_cache() {
        let id = |number| ObjectId {
            number,
            generation: 0,
        };
        let mut objects = ParameterCache::new(32);
        assert_eq!(
            objects.insert(id(1), Origin::Uncompressed, Box::from(b"2 0 R".as_slice())),
            Some(())
        );
        assert_eq!(
            objects.insert(id(2), Origin::Compressed, Box::from(b"42".as_slice())),
            Some(())
        );
        assert!(matches!(
            objects
                .scoped(Access::Document)
                .resolve(Value::Reference(id(1))),
            Ok(Value::Unsigned(42))
        ));
        assert!(matches!(
            objects
                .scoped(Access::Uncompressed)
                .resolve(Value::Reference(id(1))),
            Err(ParameterError::Invalid)
        ));
    }
}
