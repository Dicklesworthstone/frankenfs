//! Read native DSL property values and their provenance in one committed MOS.
//!
//! OpenZFS zfs-2.3.0 dsl_prop.c: local overrides received; $inherit suppresses
//! received, not local; known $iuv indexes precede local on directories only.
//! Snapshot-local properties live in ds_props_obj and may be newer than the
//! snapshot's data root. Inheritance follows dd_parent_obj, never clone origins.
//! This is inspection, not mount policy, ACL enforcement, or write admission.

use super::{Cx, FfsError, Object, Objects, Result, checkpoint, corrupt, parse, unsupported};
use ffs_ondisk::zfs_zap::Entry;
use std::collections::{BTreeMap, BTreeSet};

const MAX_QUERIES: usize = 128;
const MAX_VALUE_BYTES: usize = 8192;
const MAX_CATALOG_BYTES: usize = 32 * 1024 * 1024;
const MAX_CATALOG_ENTRIES: usize = 65_536;

type Catalog = BTreeMap<Vec<u8>, Entry>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    Number(u64),
    /// Native bytes without the required terminating NUL. Not lossy UTF-8.
    Text(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertySource {
    Local,
    Received,
    Inherited,
    Default,
    Unset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub value: Option<PropertyValue>,
    pub source: PropertySource,
    /// Pool-relative native components of the actual supplying directory.
    pub setpoint: Option<Vec<Vec<u8>>>,
    /// Present only when the supplying object is this exact named snapshot.
    pub setpoint_snapshot: Option<Vec<u8>>,
    /// How the supplying object stored the value, even when source is inherited.
    pub stored_source: Option<PropertySource>,
    /// The target's received value, including when overridden or suppressed.
    pub received: Option<PropertyValue>,
}

#[derive(Debug)]
pub struct Properties {
    pub pool_guid: u64,
    /// Property state is from this committed MOS, also for snapshot targets.
    pub pool_txg: u64,
    pub dataset_guid: u64,
    pub dataset_object: u64,
    pub components: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub snapshot_creation_txg: Option<u64>,
    pub values: Vec<Property>,
}

#[derive(Clone, Copy)]
enum DefaultValue {
    Number(u64),
    Text(&'static [u8]),
    User,
}

#[derive(Clone, Copy)]
enum Index {
    None,
    Range(u64, u64),
    Checksum,
    /// Includes the pinned native synthetic zstd and zstd-fast levels.
    Compression,
}

struct Spec {
    default: DefaultValue,
    inheritable: bool,
    filesystem: bool,
    volume: bool,
    snapshot: bool,
    index: Index,
}

impl Spec {
    fn named(name: &str) -> Result<Self> {
        if name.is_empty()
            || name.len() >= 256
            || name.starts_with('-')
            || !name.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b':' | b'-' | b'_' | b'.')
            })
        {
            return Err(corrupt("invalid native property name"));
        }
        if name.contains(':') {
            return Ok(Self {
                default: DefaultValue::User,
                inheritable: true,
                filesystem: true,
                volume: true,
                snapshot: true,
                index: Index::None,
            });
        }
        let (default, inheritable, filesystem, volume, snapshot, index) = match name {
            "atime" | "relatime" | "overlay" => (
                DefaultValue::Number(1),
                true,
                true,
                false,
                false,
                Index::Range(0, 1),
            ),
            "devices" | "exec" | "setuid" => (
                DefaultValue::Number(1),
                true,
                true,
                false,
                true,
                Index::Range(0, 1),
            ),
            "readonly" | "snapdev" | "logbias" => (
                DefaultValue::Number(0),
                true,
                true,
                true,
                false,
                Index::Range(0, 1),
            ),
            "zoned" | "vscan" => (
                DefaultValue::Number(0),
                true,
                true,
                false,
                false,
                Index::Range(0, 1),
            ),
            "nbmand" => (
                DefaultValue::Number(0),
                true,
                true,
                false,
                true,
                Index::Range(0, 1),
            ),
            "canmount" => (
                DefaultValue::Number(1),
                false,
                true,
                false,
                false,
                Index::Range(0, 2),
            ),
            "snapdir" => (
                DefaultValue::Number(0),
                true,
                true,
                false,
                false,
                Index::Range(0, 2),
            ),
            "sync" => (
                DefaultValue::Number(0),
                true,
                true,
                true,
                false,
                Index::Range(0, 2),
            ),
            "copies" => (
                DefaultValue::Number(1),
                true,
                true,
                true,
                false,
                Index::Range(1, 3),
            ),
            "checksum" => (
                DefaultValue::Number(1),
                true,
                true,
                true,
                false,
                Index::Checksum,
            ),
            "compression" => (
                DefaultValue::Number(1),
                true,
                true,
                true,
                false,
                Index::Compression,
            ),
            "recordsize" => (
                DefaultValue::Number(131_072),
                true,
                true,
                false,
                false,
                Index::None,
            ),
            "volthreading" => (
                DefaultValue::Number(1),
                false,
                false,
                true,
                false,
                Index::Range(0, 1),
            ),
            "sharenfs" | "sharesmb" => (
                DefaultValue::Text(b"off"),
                true,
                true,
                false,
                false,
                Index::None,
            ),
            "context" | "fscontext" | "defcontext" | "rootcontext" => (
                DefaultValue::Text(b"none"),
                false,
                true,
                true,
                true,
                Index::None,
            ),
            _ => {
                return Err(unsupported(format!(
                    "property {name} needs a computed value, platform default, or an unimplemented native schema"
                )));
            }
        };
        Ok(Self {
            default,
            inheritable,
            filesystem,
            volume,
            snapshot,
            index,
        })
    }

    fn default_value(&self) -> Option<PropertyValue> {
        match self.default {
            DefaultValue::Number(value) => Some(PropertyValue::Number(value)),
            DefaultValue::Text(value) => Some(PropertyValue::Text(value.to_vec())),
            DefaultValue::User => None,
        }
    }

    fn decode(&self, row: &Entry) -> Result<PropertyValue> {
        match self.default {
            DefaultValue::Number(_) => {
                if row.integer_bytes != 8 || row.values.len() != 1 {
                    return Err(corrupt("numeric DSL property is not one uint64"));
                }
                Ok(PropertyValue::Number(row.values[0]))
            }
            DefaultValue::Text(_) | DefaultValue::User => {
                if row.integer_bytes != 1
                    || row.values.is_empty()
                    || row.values.len() > MAX_VALUE_BYTES
                    || row.values.last() != Some(&0)
                {
                    return Err(corrupt(
                        "string DSL property is not a bounded NUL-terminated byte array",
                    ));
                }
                let mut text = Vec::with_capacity(row.values.len() - 1);
                for &value in &row.values[..row.values.len() - 1] {
                    let byte = u8::try_from(value)
                        .map_err(|_| corrupt("property byte overflows uint8"))?;
                    if byte == 0 {
                        return Err(corrupt("string DSL property contains an interior NUL"));
                    }
                    text.push(byte);
                }
                Ok(PropertyValue::Text(text))
            }
        }
    }

    fn known_index(&self, value: &PropertyValue) -> bool {
        let PropertyValue::Number(value) = value else {
            return false;
        };
        match self.index {
            Index::None => false,
            Index::Range(first, last) => (first..=last).contains(value),
            Index::Checksum => matches!(*value, 1 | 2 | 6..=8 | 10..=14),
            Index::Compression => {
                matches!(*value, 1..=3 | 5..=16)
                    || (*value & 127 == 16 && matches!(*value >> 7, 1..=19 | 103..=123))
            }
        }
    }
}

fn requested(names: &[String]) -> Result<Vec<Spec>> {
    if names.is_empty() || names.len() > MAX_QUERIES {
        return Err(unsupported(
            "property query requires 1 through 128 explicit names",
        ));
    }
    let mut seen = BTreeSet::new();
    names
        .iter()
        .map(|name| {
            if !seen.insert(name) {
                return Err(corrupt("duplicate requested property"));
            }
            Spec::named(name)
        })
        .collect()
}

fn received(catalog: &Catalog, name: &str, spec: &Spec) -> Result<Option<PropertyValue>> {
    catalog
        .get(format!("{name}$recvd").as_bytes())
        .map(|row| spec.decode(row))
        .transpose()
}

fn local_value(
    catalog: &Catalog,
    name: &str,
    spec: &Spec,
    snapshot: bool,
) -> Result<Option<(PropertyValue, PropertySource)>> {
    if !snapshot && let Some(row) = catalog.get(format!("{name}$iuv").as_bytes()) {
        let value = spec.decode(row)?;
        if spec.known_index(&value) {
            return Ok(Some((value, PropertySource::Local)));
        }
    }
    if let Some(row) = catalog.get(name.as_bytes()) {
        return Ok(Some((spec.decode(row)?, PropertySource::Local)));
    }
    if (!snapshot || spec.inheritable) && catalog.contains_key(format!("{name}$inherit").as_bytes())
    {
        return Ok(None);
    }
    Ok(received(catalog, name, spec)?.map(|value| (value, PropertySource::Received)))
}

struct Layer {
    object: u64,
    components: Vec<Vec<u8>>,
    snapshot: Option<Vec<u8>>,
}

struct Catalogs {
    layers: Vec<Layer>,
    cached: Vec<Option<Catalog>>,
    bytes: usize,
    entries: usize,
}

impl Catalogs {
    fn new(layers: Vec<Layer>) -> Self {
        Self {
            cached: (0..layers.len()).map(|_| None).collect(),
            layers,
            bytes: 0,
            entries: 0,
        }
    }

    fn get(&mut self, view: &mut Objects, cx: &Cx, index: usize) -> Result<&Catalog> {
        checkpoint(cx)?;
        if self.cached[index].is_none() {
            let object = self.layers[index].object;
            let rows = if object == 0 {
                Vec::new()
            } else {
                let node = view.object(cx, object)?;
                if !matches!(node.object_type(), 15 | 196) {
                    return Err(corrupt("DSL property catalog has the wrong object type"));
                }
                view.zap_values(cx, object)?
            };
            let mut catalog = Catalog::new();
            for row in rows {
                checkpoint(cx)?;
                let bytes = row
                    .values
                    .len()
                    .checked_mul(8)
                    .and_then(|size| size.checked_add(row.name.len() * 2))
                    .and_then(|size| size.checked_add(std::mem::size_of::<Entry>()))
                    .ok_or_else(|| corrupt("property catalog size overflow"))?;
                self.bytes = self
                    .bytes
                    .checked_add(bytes)
                    .filter(|size| *size <= MAX_CATALOG_BYTES)
                    .ok_or_else(|| unsupported("property catalogs exceed 32 MiB payload budget"))?;
                self.entries += 1;
                if self.entries > MAX_CATALOG_ENTRIES {
                    return Err(unsupported("property catalogs exceed 65536 entries"));
                }
                if catalog.insert(row.name.clone(), row).is_some() {
                    return Err(corrupt("duplicate DSL property storage key"));
                }
            }
            self.cached[index] = Some(catalog);
        }
        self.cached[index]
            .as_ref()
            .ok_or_else(|| corrupt("missing property catalog cache"))
    }

    fn resolve(
        &mut self,
        view: &mut Objects,
        cx: &Cx,
        name: &str,
        spec: &Spec,
    ) -> Result<Property> {
        let recvd = received(self.get(view, cx, 0)?, name, spec)?;
        let mut result = Property {
            name: name.into(),
            value: spec.default_value(),
            source: if matches!(spec.default, DefaultValue::User) {
                PropertySource::Unset
            } else {
                PropertySource::Default
            },
            setpoint: None,
            setpoint_snapshot: None,
            stored_source: None,
            received: recvd,
        };
        for index in 0..self.layers.len() {
            checkpoint(cx)?;
            if index != 0 && !spec.inheritable {
                break;
            }
            let snapshot = self.layers[index].snapshot.is_some();
            if let Some((value, source)) =
                local_value(self.get(view, cx, index)?, name, spec, snapshot)?
            {
                let layer = &self.layers[index];
                result.value = Some(value);
                result.source = if index == 0 {
                    source
                } else {
                    PropertySource::Inherited
                };
                result.setpoint = Some(layer.components.clone());
                result.setpoint_snapshot.clone_from(&layer.snapshot);
                result.stored_source = Some(source);
                break;
            }
        }
        Ok(result)
    }
}

fn bonus_word(object: &Object, at: usize) -> Result<u64> {
    object
        .node
        .order()
        .u64(object.node.bonus(), at)
        .map_err(|error| parse(&error))
}

impl Objects {
    /// Resolve explicit property queries against this MOS without opening a ZPL
    /// mount. Snapshot property state remains at pool_txg, not creation_txg.
    /// Numeric/index values are native integers, not host policy or codec support.
    pub fn properties(
        &mut self,
        cx: &Cx,
        components: &[Vec<u8>],
        snapshot: Option<&[u8]>,
        names: &[String],
    ) -> Result<Properties> {
        checkpoint(cx)?;
        let specs = requested(names)?;
        let dataset = self
            .datasets(cx)?
            .into_iter()
            .find(|row| row.components == components)
            .ok_or_else(|| FfsError::NotFound("ZFS property dataset".into()))?;
        for spec in &specs {
            let admitted = if snapshot.is_some() {
                spec.snapshot
            } else {
                match dataset.objectset_kind {
                    Some(2) => spec.filesystem,
                    Some(3) => spec.volume,
                    _ => false,
                }
            };
            if !admitted {
                return Err(unsupported(
                    "requested property does not apply to this dataset type",
                ));
            }
        }
        let mut report = Properties {
            pool_guid: self.pool_guid(),
            pool_txg: self.txg,
            dataset_guid: dataset.guid,
            dataset_object: dataset.head_object,
            components: components.to_vec(),
            snapshot: snapshot.map(<[u8]>::to_vec),
            snapshot_creation_txg: None,
            values: Vec::with_capacity(names.len()),
        };
        let mut layers = Vec::new();
        let mut catalogs = BTreeSet::new();
        if snapshot.is_none() && bonus_word(&self.load(cx, dataset.head_object)?, 264)? != 0 {
            return Err(corrupt("head dataset has snapshot-only property storage"));
        }
        if let Some(name) = snapshot {
            let selected = self.named_snapshot_root(cx, components, name)?;
            let object = self.load(cx, selected.info.object)?;
            let props = bonus_word(&object, 264)?;
            if props != 0 {
                catalogs.insert(props);
            }
            layers.push(Layer {
                object: props,
                components: components.to_vec(),
                snapshot: Some(name.to_vec()),
            });
            report.dataset_guid = selected.info.guid;
            report.dataset_object = selected.info.object;
            report.snapshot_creation_txg = Some(selected.info.creation_txg);
        }
        let mut number = dataset.directory_object;
        let mut path = components.to_vec();
        let mut directories = BTreeSet::new();
        loop {
            checkpoint(cx)?;
            if number == 0 || directories.len() >= 65 || !directories.insert(number) {
                return Err(corrupt("invalid or cyclic property inheritance directory"));
            }
            let object = self.load(cx, number)?;
            let node = &object.node;
            if !matches!(node.object_type(), 12 | 196)
                || node.bonus_type() != 12
                || node.bonus().len() != 256
                || node.spill().is_some()
            {
                return Err(corrupt("property ancestor is not a native DSL directory"));
            }
            let parent = bonus_word(&object, 16)?;
            let props = bonus_word(&object, 80)?;
            if props <= 1 || !catalogs.insert(props) {
                return Err(corrupt("missing or aliased DSL property catalog"));
            }
            layers.push(Layer {
                object: props,
                components: path.clone(),
                snapshot: None,
            });
            if path.is_empty() {
                if parent != 0 {
                    return Err(corrupt("property root has a foreign parent"));
                }
                break;
            }
            if parent == 0 {
                return Err(corrupt("property ancestry ends before selected root"));
            }
            path.pop();
            number = parent;
        }
        if catalogs
            .iter()
            .any(|id| directories.contains(id) || *id == report.dataset_object)
        {
            return Err(corrupt("property catalog aliases its DSL owner"));
        }
        let mut catalogs = Catalogs::new(layers);
        for (name, spec) in names.iter().zip(specs) {
            report.values.push(catalogs.resolve(self, cx, name, &spec)?);
        }
        checkpoint(cx)?;
        Ok(report)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
