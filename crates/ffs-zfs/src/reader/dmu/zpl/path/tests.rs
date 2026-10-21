//! Constructed checksum-protected DMU/ZPL graphs, not native OpenZFS evidence.
//! The view opens through ZPL master/root validation. Labels/MOS admission have
//! separate tests; every namespace and long-link read uses the production reader.
use super::*;
use crate::reader::dmu::Objects;
use crate::reader::{ByteOffset, Leaf, VdevConfig};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::{DATA_OFFSET, Endian, checksum};
use ffs_ondisk::zfs_dmu::Dnode;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const BASE: u64 = 1024;
const LENGTH: u64 = 16 * 1024 * 1024;
const TABLE: u64 = DATA_OFFSET + 0x10000;
type Reads = Arc<Mutex<Vec<u64>>>;

fn address(id: u64) -> u64 {
    DATA_OFFSET + 0x20000 + id * 0x20000
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Io(u64),
    Cancel(u64),
    Corrupt(u64),
}

struct Device {
    blocks: BTreeMap<u64, Vec<u8>>,
    reads: Reads,
    fault: Fault,
}
impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        BASE + LENGTH
    }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.lock().unwrap().push(offset.0);
        match self.fault {
            Fault::Cancel(at) if at + BASE == offset.0 => return Err(FfsError::Cancelled),
            Fault::Io(at) if at + BASE == offset.0 => {
                return Err(corrupt("injected path I/O failure"));
            }
            _ => {}
        }
        let (base, bytes) = self
            .blocks
            .range(..=offset.0)
            .next_back()
            .ok_or_else(|| corrupt("unregistered path read"))?;
        let start = usize::try_from(offset.0 - *base).unwrap();
        let bytes = bytes
            .get(start..start + out.len())
            .ok_or_else(|| corrupt("short path fixture"))?;
        out.copy_from_slice(bytes);
        if matches!(self.fault, Fault::Corrupt(at) if at + BASE == offset.0) {
            out[0] ^= 1;
        }
        checkpoint(cx)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("path resolution wrote storage")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("path resolution flushed storage")
    }
}

struct Spec {
    parent: u64,
    kind: Kind,
    data: Vec<u8>,
    entries: Vec<(Vec<u8>, u64)>,
    inline: bool,
}
impl Spec {
    fn directory(parent: u64, entries: &[(&[u8], u64)]) -> Self {
        Self {
            parent,
            kind: Kind::Directory,
            data: Vec::new(),
            entries: entries
                .iter()
                .map(|(name, id)| (name.to_vec(), *id))
                .collect(),
            inline: false,
        }
    }
    fn file(parent: u64, data: &[u8]) -> Self {
        Self {
            parent,
            kind: Kind::Regular,
            data: data.to_vec(),
            entries: Vec::new(),
            inline: false,
        }
    }
    fn link(parent: u64, target: &[u8], inline: bool) -> Self {
        Self {
            parent,
            kind: Kind::Symlink,
            data: target.to_vec(),
            entries: Vec::new(),
            inline,
        }
    }
}

fn basic() -> BTreeMap<u64, Spec> {
    BTreeMap::from([
        (
            2,
            Spec::directory(
                2,
                &[
                    (b"file", 3),
                    (b"d", 4),
                    (b"link", 5),
                    (b"dirlink", 6),
                    (b"again", 7),
                    (b"absolute", 8),
                ],
            ),
        ),
        (3, Spec::file(2, b"ROOT")),
        (
            4,
            Spec::directory(2, &[(b"file", 9), (b"same", 5), (b"up", 10)]),
        ),
        (5, Spec::link(2, b"file", true)),
        (6, Spec::link(2, b"d", true)),
        (7, Spec::link(2, b".", true)),
        (8, Spec::link(2, b"/file", true)),
        (9, Spec::file(4, b"CHILD")),
        (10, Spec::link(4, b"../file", true)),
    ])
}

fn tag(kind: Kind) -> u64 {
    match kind {
        Kind::Directory => 4,
        Kind::Regular => 8,
        Kind::Symlink => 10,
        _ => panic!("unsupported test kind"),
    }
}
fn word(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn short(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    raw[at..at + 2].copy_from_slice(&match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}
fn micro(entries: &[(Vec<u8>, u64)], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; (64 + entries.len() * 64).next_power_of_two().max(512)];
    word(&mut raw, 0, (1_u64 << 63) + 3, order);
    for (index, (name, value)) in entries.iter().enumerate() {
        assert!(name.len() < 50);
        let at = 64 + index * 64;
        word(&mut raw, at, *value, order);
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}
fn pointer(
    data: &[u8],
    at: u64,
    kind: u8,
    birth: u64,
    order: Endian,
    payload: Endian,
) -> [u8; 128] {
    let sectors = data.len() as u64 / 512;
    let mut raw = [0; 128];
    word(&mut raw, 0, sectors, order);
    word(&mut raw, 8, (at - DATA_OFFSET) / 512, order);
    word(
        &mut raw,
        48,
        (sectors - 1)
            | ((sectors - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(payload == Endian::Little) << 63),
        order,
    );
    word(&mut raw, 80, birth, order);
    for (index, sum) in checksum(data, 7, payload).unwrap().into_iter().enumerate() {
        word(&mut raw, 96 + index * 8, sum, order);
    }
    raw
}
fn node(kind: u8, data: &[u8], at: u64, bonus: &[u8], order: Endian, payload: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[4] = if bonus.is_empty() { 0 } else { 17 };
    raw[7] = 1;
    short(&mut raw, 8, (data.len().max(512) / 512) as u16, order);
    short(&mut raw, 10, bonus.len() as u16, order);
    if !data.is_empty() {
        raw[64..192].copy_from_slice(&pointer(data, at, kind, 20, order, payload));
    }
    raw[192..192 + bonus.len()].copy_from_slice(bonus);
    raw
}

fn build(specs: &BTreeMap<u64, Spec>, order: Endian, fault: Fault) -> (Zpl, Reads) {
    let cx = Cx::for_testing();
    let payload = if order == Endian::Little {
        Endian::Big
    } else {
        Endian::Little
    };
    let mut blocks = BTreeMap::new();
    let mut table = vec![0; 16384];
    let master = micro(&[(b"ROOT".to_vec(), 2), (b"VERSION".to_vec(), 4)], payload);
    table[512..1024].copy_from_slice(&node(21, &master, address(1), &[], order, payload));
    blocks.insert(BASE + address(1), master);
    for (&id, spec) in specs {
        assert!((2..32).contains(&id));
        let mut bonus = vec![0; 264];
        for (at, value) in [
            (64, 10),
            (72, (tag(spec.kind) << 12) | 0o444),
            (80, spec.data.len() as u64),
            (88, spec.parent),
            (96, 2),
        ] {
            word(&mut bonus, at, value, order);
        }
        let kind = if spec.kind == Kind::Directory { 20 } else { 19 };
        let data = if spec.kind == Kind::Directory {
            let entries = spec
                .entries
                .iter()
                .map(|(name, id)| (name.clone(), (tag(specs[id].kind) << 60) | id))
                .collect::<Vec<_>>();
            micro(&entries, payload)
        } else if spec.kind == Kind::Symlink && spec.inline {
            assert!(spec.data.len() <= 56);
            bonus.extend_from_slice(&spec.data);
            Vec::new()
        } else {
            let mut bytes = spec.data.clone();
            bytes.resize(bytes.len().next_power_of_two().max(512), 0);
            bytes
        };
        let at = usize::try_from(id).unwrap() * 512;
        table[at..at + 512].copy_from_slice(&node(
            kind,
            &data,
            address(id),
            &bonus,
            order,
            payload,
        ));
        if !data.is_empty() {
            blocks.insert(BASE + address(id), data);
        }
    }
    let mut meta = node(10, &table, TABLE, &[], payload, order);
    meta[64..192].copy_from_slice(&pointer(&table, TABLE, 10, 30, payload, order));
    blocks.insert(BASE + TABLE, table);
    let reads = Arc::new(Mutex::new(Vec::new()));
    let leaf = Leaf::from_device(
        &cx,
        Box::new(Device {
            blocks,
            reads: Arc::clone(&reads),
            fault,
        }),
        BASE,
        LENGTH,
    )
    .unwrap();
    let objects = Objects {
        pool: leaf.into(),
        config: VdevConfig {
            pool_guid: 1,
            top_guid: 2,
            version: 28,
            txg: 40,
            ashift: 9,
            id: 0,
            allocated_bytes: LENGTH - DATA_OFFSET - 2 * 256 * 1024,
            read_features: Vec::new(),
            raidz_members: None,
        },
        txg: 40,
        root_birth: 35,
        meta: Dnode::parse(&meta, payload).unwrap(),
        cache: VecDeque::new(),
        cached_bytes: 0,
    };
    let view = Zpl::open(
        &cx,
        objects,
        987,
        4096,
        ffs_ondisk::zfs_dmu::ZilHeader::parse(&[0_u8; 192], order).unwrap(),
        None,
    )
    .unwrap();
    (view, reads)
}

fn resolve(view: &mut Zpl, path: &[u8], policy: PathPolicy) -> Result<u64> {
    view.resolve_with(&Cx::for_testing(), path, policy)
}
fn is_loop(result: Result<u64>) -> bool {
    matches!(result, Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::ELOOP))
}

#[test]
fn policies_distinguish_final_link_inspection_from_ancestor_traversal() {
    for order in [Endian::Little, Endian::Big] {
        let (mut view, _) = build(&basic(), order, Fault::None);
        assert_eq!(view.resolve(&Cx::for_testing(), b"/link").unwrap(), 5);
        assert_eq!(
            resolve(&mut view, b"/link", PathPolicy::NoFollowFinal).unwrap(),
            5
        );
        assert_eq!(resolve(&mut view, b"/link", PathPolicy::Follow).unwrap(), 3);
        assert_eq!(
            resolve(&mut view, b"/dirlink/same", PathPolicy::NoFollowFinal).unwrap(),
            5
        );
        assert_eq!(
            resolve(&mut view, b"/dirlink/same", PathPolicy::Follow).unwrap(),
            9
        );
        assert!(is_loop(resolve(
            &mut view,
            b"/dirlink/file",
            PathPolicy::NoSymlinks
        )));
        assert_eq!(view.readlink(&Cx::for_testing(), 5).unwrap(), b"file");
        assert!(view.read(&Cx::for_testing(), 5, 0, 4).is_err());
    }
}

#[test]
fn relative_links_use_encountered_directory_not_symlink_stored_parent() {
    for order in [Endian::Little, Endian::Big] {
        let (mut view, _) = build(&basic(), order, Fault::None);
        let root = resolve(&mut view, b"link", PathPolicy::Follow).unwrap();
        let child = resolve(&mut view, b"d/same", PathPolicy::Follow).unwrap();
        assert_eq!(view.read(&Cx::for_testing(), root, 0, 64).unwrap(), b"ROOT");
        assert_eq!(
            view.read(&Cx::for_testing(), child, 0, 64).unwrap(),
            b"CHILD"
        );
        assert_eq!(
            resolve(&mut view, b"d/up", PathPolicy::Follow).unwrap(),
            root
        );
        assert_eq!(
            resolve(&mut view, b"dirlink/../d/../file", PathPolicy::Follow).unwrap(),
            root
        );
    }
}

#[test]
fn absolute_targets_reset_to_selected_dataset_and_cannot_escape_it() {
    let mut specs = basic();
    specs.insert(5, Spec::link(2, b"/file", true));
    let (mut view, _) = build(&specs, Endian::Big, Fault::None);
    assert_eq!(
        resolve(&mut view, b"d/same", PathPolicy::Follow).unwrap(),
        3
    );
    for path in [b"../file".as_slice(), b"d/../../file", b"/../../file"] {
        assert!(matches!(
            resolve(&mut view, path, PathPolicy::Follow),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    for target in [b"../file".as_slice(), b"/../file", b"d/../../file"] {
        specs.insert(5, Spec::link(2, target, true));
        let (mut view, _) = build(&specs, Endian::Little, Fault::None);
        assert!(matches!(
            resolve(&mut view, b"link", PathPolicy::Follow),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    specs.insert(5, Spec::link(2, b"///", true));
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    assert_eq!(
        resolve(&mut view, b"link/file", PathPolicy::Follow).unwrap(),
        3
    );
}

#[test]
fn trailing_slashes_and_dot_components_are_not_lexically_erased() {
    let (mut view, _) = build(&basic(), Endian::Little, Fault::None);
    for path in [
        b"file/.".as_slice(),
        b"file/../file",
        b"link/",
        b"link/../file",
    ] {
        assert!(matches!(
            resolve(&mut view, path, PathPolicy::Follow),
            Err(FfsError::NotDirectory)
        ));
    }
    assert_eq!(
        resolve(&mut view, b"dirlink/", PathPolicy::NoFollowFinal).unwrap(),
        4
    );
    assert_eq!(
        resolve(&mut view, b"dirlink/.", PathPolicy::NoFollowFinal).unwrap(),
        4
    );
    for target in [b"file/".as_slice(), b"file/../file", b"file/."] {
        let mut specs = basic();
        specs.insert(5, Spec::link(2, target, true));
        let (mut view, _) = build(&specs, Endian::Big, Fault::None);
        assert!(matches!(
            resolve(&mut view, b"link", PathPolicy::Follow),
            Err(FfsError::NotDirectory)
        ));
    }
}

#[test]
fn loops_are_bounded_but_revisiting_a_link_in_a_finite_path_is_legal() {
    let cx = Cx::for_testing();
    let (mut view, _) = build(&basic(), Endian::Little, Fault::None);
    let path = format!("{}file", "again/".repeat(MAX_SYMLINKS));
    assert_eq!(
        view.resolve_with(&cx, path.as_bytes(), PathPolicy::Follow)
            .unwrap(),
        3
    );
    let path = format!("{}file", "again/".repeat(MAX_SYMLINKS + 1));
    assert!(is_loop(resolve(
        &mut view,
        path.as_bytes(),
        PathPolicy::Follow
    )));
    for target in [b"link".as_slice(), b"absolute"] {
        let mut specs = basic();
        specs.insert(5, Spec::link(2, target, true));
        specs.insert(8, Spec::link(2, b"link", true));
        let (mut view, _) = build(&specs, Endian::Big, Fault::None);
        assert!(is_loop(resolve(&mut view, b"link", PathPolicy::Follow)));
    }
}

#[test]
fn long_targets_are_checksum_checked_and_cancellation_stops_at_the_failed_read() {
    let target = format!("{}file", "./".repeat(30));
    let mut specs = basic();
    specs.insert(5, Spec::link(2, target.as_bytes(), false));
    for order in [Endian::Little, Endian::Big] {
        let (mut view, reads) = build(&specs, order, Fault::None);
        let id = resolve(&mut view, b"link", PathPolicy::Follow).unwrap();
        assert_eq!(id, 3);
        assert!(reads.lock().unwrap().contains(&(BASE + address(5))));
        for fault in [
            Fault::Io(address(5)),
            Fault::Cancel(address(5)),
            Fault::Corrupt(address(5)),
        ] {
            let (mut view, reads) = build(&specs, order, fault);
            assert_eq!(
                resolve(&mut view, b"link", PathPolicy::NoFollowFinal).unwrap(),
                5
            );
            assert!(!reads.lock().unwrap().contains(&(BASE + address(5))));
            for _ in 0..2 {
                let result = resolve(&mut view, b"link", PathPolicy::Follow);
                if matches!(fault, Fault::Cancel(_)) {
                    assert!(matches!(result, Err(FfsError::Cancelled)));
                } else {
                    assert!(result.is_err());
                }
                assert_eq!(reads.lock().unwrap().last(), Some(&(BASE + address(5))));
            }
            assert_eq!(
                reads
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|&&at| at == BASE + address(5))
                    .count(),
                2
            );
            assert!(!reads.lock().unwrap().contains(&(BASE + address(3))));
        }
    }
}

#[test]
fn cumulative_text_and_component_limits_apply_across_link_expansions() {
    let mut specs = basic();
    specs.insert(
        5,
        Spec::link(2, format!("{}file", "./".repeat(128)).as_bytes(), false),
    );
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    let path = format!("{}link", "./".repeat(128));
    assert!(matches!(
        resolve(&mut view, path.as_bytes(), PathPolicy::Follow),
        Err(FfsError::NameTooLong)
    ));
    specs.insert(5, Spec::link(2, &vec![b'/'; MAX_PATH], false));
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    assert!(matches!(
        resolve(&mut view, b"link", PathPolicy::Follow),
        Err(FfsError::NameTooLong)
    ));
    assert!(matches!(
        resolve(&mut view, &vec![b'/'; MAX_PATH + 1], PathPolicy::Follow),
        Err(FfsError::NameTooLong)
    ));
    assert!(matches!(
        resolve(&mut view, &vec![b'a'; 256], PathPolicy::Follow),
        Err(FfsError::NameTooLong)
    ));
}

#[test]
fn empty_and_nul_targets_never_become_the_containing_directory() {
    let mut specs = basic();
    specs.insert(5, Spec::link(2, b"", true));
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    assert!(matches!(
        resolve(&mut view, b"link", PathPolicy::Follow),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(
        resolve(&mut view, b"link", PathPolicy::NoFollowFinal).unwrap(),
        5
    );
    specs.insert(5, Spec::link(2, b"file\0ignored", false));
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    assert!(resolve(&mut view, b"link", PathPolicy::Follow).is_err());
    assert!(resolve(&mut view, b"file\0ignored", PathPolicy::Follow).is_err());
    assert_eq!(resolve(&mut view, b"", PathPolicy::Follow).unwrap(), 2);
}

#[test]
fn raw_name_bytes_are_preserved_and_utf8_only_policy_is_not_bypassed_by_links() {
    let mut specs = basic();
    specs.get_mut(&2).unwrap().entries.push((vec![0xff], 3));
    specs.insert(5, Spec::link(2, &[0xff], true));
    let (mut view, _) = build(&specs, Endian::Big, Fault::None);
    assert_eq!(resolve(&mut view, b"link", PathPolicy::Follow).unwrap(), 3);
    view.utf8_only = true;
    assert!(resolve(&mut view, b"link", PathPolicy::Follow).is_err());
}

#[test]
fn corrupt_directory_metadata_cannot_hide_behind_an_earlier_matching_link() {
    let mut specs = basic();
    specs.get_mut(&4).unwrap().parent = 99;
    let (mut view, _) = build(&specs, Endian::Little, Fault::None);
    assert!(resolve(&mut view, b"link", PathPolicy::Follow).is_err());
    let (mut view, reads) = build(&basic(), Endian::Little, Fault::Corrupt(address(2)));
    assert!(resolve(&mut view, b"link", PathPolicy::Follow).is_err());
    assert!(!reads.lock().unwrap().contains(&(BASE + address(3))));
}

#[test]
fn directory_work_is_charged_even_when_metadata_is_already_cached() {
    let cx = Cx::for_testing();
    let (mut view, _) = build(&basic(), Endian::Little, Fault::None);
    let entries = view.list(&cx, 2).unwrap();
    let mut walk = Walk::new(b"file").unwrap();
    walk.directory(&cx, &entries).unwrap();
    let used = walk.directory_work;
    walk.directory_work = MAX_DIRECTORY_WORK - used;
    walk.directory(&cx, &entries).unwrap();
    assert_eq!(walk.directory_work, MAX_DIRECTORY_WORK);
    assert!(matches!(
        walk.directory(&cx, &entries),
        Err(FfsError::UnsupportedFeature(_))
    ));
}
