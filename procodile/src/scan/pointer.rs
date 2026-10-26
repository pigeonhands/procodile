//! Pointer scanning: finding chains of pointers from static memory to an address, so a
//! value can be found again after the process restarts and its heap moves.
//!
//! The scan builds a reverse map of every pointer in memory (value -> where it is stored),
//! then walks backwards from the target: anything pointing at most `max_offset` bytes below
//! the target is a candidate parent, and so on up to `max_depth` levels. Parents inside a
//! module are static bases, which end a path.
//!
//! The reverse map is a [`PointerMap`], which can be saved and scanned later without the
//! process. Comparing paths across maps taken from several runs (with the target value
//! found again in each) is the most reliable way to find paths that survive restarts.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Range;
use std::str::FromStr;

use super::{Progress, chunks_where, par_map};
use crate::{Address, Error, Module, ProcessHandle, RegionKind, Result};

/// Stop expanding once this many intermediate addresses have been reached, to bound memory
/// and time on dense heaps.
const MAX_NODES: usize = 4_000_000;

#[derive(Debug, Clone)]
pub struct PointerMapOptions {
    /// Only record pointers stored in writable memory, where almost all data pointers
    /// live. Turning this off also records read-only data such as `.data.rel.ro`.
    pub writable_only: bool,
    /// Worker threads; `0` means one per CPU.
    pub threads: usize,
}

impl Default for PointerMapOptions {
    fn default() -> Self {
        Self {
            writable_only: true,
            threads: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PointerScanOptions {
    /// Maximum number of pointer dereferences in a path.
    pub max_depth: usize,
    /// Maximum offset added after each dereference (structure field offset).
    pub max_offset: usize,
    /// Stop after this many paths.
    pub max_results: usize,
}

impl Default for PointerScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_offset: 0x1000,
            max_results: 10_000,
        }
    }
}

/// A pointer path: `[[module+module_offset]+offsets[0]]+...+offsets[n-1]`.
///
/// Resolving it reads the pointer stored at `module + module_offset`, adds `offsets[0]`,
/// reads the pointer there, and so on; the last offset is added without a read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointerPath {
    /// The module's file name, e.g. `game.exe`.
    pub module: String,
    pub module_offset: usize,
    pub offsets: Vec<usize>,
}

impl PointerPath {
    /// Follows the path in `handle`. `modules` is the result of [`ProcessHandle::modules`]
    /// and `pointer_width` of [`ProcessHandle::pointer_width`], passed in so that many
    /// paths can be resolved cheaply.
    pub fn resolve(
        &self,
        handle: &ProcessHandle,
        modules: &[Module],
        pointer_width: usize,
    ) -> Result<Address> {
        let module = modules
            .iter()
            .find(|m| m.name.to_string_lossy() == self.module)
            .ok_or_else(|| Error::InvalidScan(format!("module '{}' is not loaded", self.module)))?;
        // A stale path can read garbage, so the arithmetic must not overflow.
        let overflow = || Error::InvalidScan(format!("pointer path {self} leads out of range"));
        let mut address = module
            .base
            .checked_add(self.module_offset)
            .ok_or_else(overflow)?;
        for &offset in &self.offsets {
            address = handle
                .read_pointer(address, pointer_width)?
                .checked_add(offset)
                .ok_or_else(overflow)?;
        }
        Ok(address)
    }

    /// Number of dereferences.
    pub fn depth(&self) -> usize {
        self.offsets.len()
    }
}

/// Formats as an address expression: `[["game.exe"+0x1234]+0x10]+0x8`, with the module
/// name quoted only when needed.
impl fmt::Display for PointerPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plain = self
            .module
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
            && self
                .module
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.');
        let mut s = if plain {
            format!("{}+{:#x}", self.module, self.module_offset)
        } else {
            format!("\"{}\"+{:#x}", self.module, self.module_offset)
        };
        for offset in &self.offsets {
            s = format!("[{s}]+{offset:#x}");
        }
        f.write_str(&s)
    }
}

/// Parses the [`Display`](fmt::Display) form.
impl FromStr for PointerPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let err = || Error::InvalidScan(format!("invalid pointer path '{s}'"));
        let s = s.trim();
        let depth = s.chars().take_while(|&c| c == '[').count();
        let mut rest = &s[depth..];

        let (module, after) = if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').ok_or_else(err)?;
            (&quoted[..end], &quoted[end + 1..])
        } else {
            let end = rest.find('+').ok_or_else(err)?;
            (&rest[..end], &rest[end..])
        };
        rest = after;

        let mut numbers = Vec::with_capacity(depth + 1);
        for i in 0..=depth {
            rest = rest.strip_prefix('+').ok_or_else(err)?;
            let end = rest.find(']').unwrap_or(rest.len());
            let digits = rest[..end].trim();
            let digits = digits.strip_prefix("0x").ok_or_else(err)?;
            numbers.push(usize::from_str_radix(digits, 16).map_err(|_| err())?);
            rest = &rest[end..];
            if i < depth {
                rest = rest.strip_prefix(']').ok_or_else(err)?;
            }
        }
        if !rest.is_empty() || module.is_empty() {
            return Err(err());
        }
        Ok(PointerPath {
            module: module.to_owned(),
            module_offset: numbers[0],
            offsets: numbers[1..].to_vec(),
        })
    }
}

/// A module as recorded in a [`PointerMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapModule {
    pub name: String,
    pub base: Address,
    /// Where pointer paths may start: the image, plus on Linux the anonymous `.bss`
    /// mapping directly after it.
    pub statics: Range<Address>,
}

/// A snapshot of every pointer in a process: aligned pointer-sized values in scanned memory
/// that point into a readable region, with where each is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerMap {
    pointer_width: usize,
    /// Sorted by `statics.start`.
    modules: Vec<MapModule>,
    /// `(value, location)`, sorted by value, for walking backwards.
    by_value: Vec<(usize, usize)>,
    /// `(location, value)`, sorted by location, for resolving paths.
    by_location: Vec<(usize, usize)>,
}

const MAGIC: &[u8; 8] = b"PCDLPMAP";
const VERSION: u32 = 1;

impl PointerMap {
    pub fn build(
        handle: &ProcessHandle,
        options: &PointerMapOptions,
        progress: Option<&Progress>,
    ) -> Result<PointerMap> {
        let fallback = Progress::new();
        let progress = progress.unwrap_or(&fallback);
        let width = handle.pointer_width()?;
        let regions = handle.regions()?;
        let valid: Vec<Range<usize>> = regions
            .iter()
            .filter(|r| r.protection.readable())
            .map(|r| r.base.get()..r.end().get())
            .collect();

        let chunks = chunks_where(handle, None, width, |r| {
            (!options.writable_only || r.protection.writable()) && r.kind != RegionKind::Mapped
        })?;
        progress.start(chunks.iter().map(|c| c.positions as u64).sum());
        let threads = match options.threads {
            0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        };
        let parts = par_map(&chunks, threads, |chunk| {
            let mut out = Vec::new();
            if progress.is_cancelled() {
                return out;
            }
            let mut bytes = vec![0; chunk.len];
            let read = handle.read_bytes(chunk.base, &mut bytes).unwrap_or(0);
            let base = chunk.base.get();
            let first = (width - base % width) % width;
            let end = chunk.positions.min((read + 1).saturating_sub(width));
            for off in (first..end.max(first)).step_by(width) {
                let value = read_word(&bytes[off..off + width]);
                if is_valid(&valid, value) {
                    out.push((value, base + off));
                }
            }
            progress.advance(chunk.positions);
            out
        });
        if progress.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let modules = handle
            .modules()?
            .iter()
            .map(|m| {
                let mut end = m.end();
                if let Some(bss) = regions
                    .iter()
                    .find(|r| r.base == end && r.kind == RegionKind::Private && r.path.is_none())
                {
                    end = bss.end();
                }
                MapModule {
                    name: m.name.to_string_lossy().into_owned(),
                    base: m.base,
                    statics: m.base..end,
                }
            })
            .collect();
        Ok(Self::from_parts(
            width,
            modules,
            parts.into_iter().flatten().collect(),
        ))
    }

    fn from_parts(
        pointer_width: usize,
        mut modules: Vec<MapModule>,
        mut by_value: Vec<(usize, usize)>,
    ) -> PointerMap {
        modules.sort_by_key(|m| m.statics.start);
        by_value.sort_unstable();
        let mut by_location: Vec<(usize, usize)> = by_value.iter().map(|&(v, l)| (l, v)).collect();
        by_location.sort_unstable();
        PointerMap {
            pointer_width,
            modules,
            by_value,
            by_location,
        }
    }

    pub fn pointer_width(&self) -> usize {
        self.pointer_width
    }

    pub fn modules(&self) -> &[MapModule] {
        &self.modules
    }

    /// Number of pointers recorded.
    pub fn len(&self) -> usize {
        self.by_value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty()
    }

    /// Finds pointer paths from module statics to `target`, shortest first.
    pub fn scan(&self, target: Address, options: &PointerScanOptions) -> Vec<PointerPath> {
        let mut paths = Vec::new();
        self.scan_with(target, options, |path| {
            paths.push(path);
            true
        });
        paths.sort_by_key(|p| (p.depth(), p.offsets.iter().sum::<usize>()));
        paths
    }

    /// Like [`PointerMap::scan`], but hands each path to `emit` as it is found (shallowest
    /// bases first), stopping when `emit` returns false or `max_results` is reached.
    pub fn scan_with(
        &self,
        target: Address,
        options: &PointerScanOptions,
        mut emit: impl FnMut(PointerPath) -> bool,
    ) {
        if options.max_depth == 0 || options.max_results == 0 {
            return;
        }
        let graph = walk_back(self, target.get(), options);
        let mut count = 0;
        for &(location, module) in &graph.roots {
            let module = &self.modules[module];
            let keep_going = collect_paths(
                &graph,
                location,
                target.get(),
                &mut Vec::new(),
                &mut |offsets| {
                    count += 1;
                    emit(PointerPath {
                        module: module.name.clone(),
                        module_offset: location - module.base.get(),
                        offsets: offsets.to_vec(),
                    }) && count < options.max_results
                },
            );
            if !keep_going {
                break;
            }
        }
    }

    /// Follows `path` using the pointer values recorded in this map. Returns `None` if
    /// the module was not loaded or a pointer along the way was not recorded.
    pub fn resolve(&self, path: &PointerPath) -> Option<Address> {
        let module = self.modules.iter().find(|m| m.name == path.module)?;
        let mut address = module.base.get().checked_add(path.module_offset)?;
        for &offset in &path.offsets {
            let i = self
                .by_location
                .binary_search_by_key(&address, |&(l, _)| l)
                .ok()?;
            address = self.by_location[i].1.checked_add(offset)?;
        }
        Some(Address::new(address))
    }

    /// Keeps the paths that resolve to `target` in this map: the map's equivalent of
    /// [`filter_pointers`], for comparing against a snapshot from another run.
    pub fn filter(&self, paths: &[PointerPath], target: Address) -> Vec<PointerPath> {
        paths
            .iter()
            .filter(|p| self.resolve(p) == Some(target))
            .cloned()
            .collect()
    }

    /// Writes the map in a compact little-endian binary format.
    pub fn write_to(&self, mut w: impl Write) -> io::Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&VERSION.to_le_bytes())?;
        w.write_all(&(self.pointer_width as u32).to_le_bytes())?;
        w.write_all(&(self.modules.len() as u64).to_le_bytes())?;
        for m in &self.modules {
            w.write_all(&(m.name.len() as u64).to_le_bytes())?;
            w.write_all(m.name.as_bytes())?;
            for n in [m.base, m.statics.start, m.statics.end] {
                w.write_all(&(n.get() as u64).to_le_bytes())?;
            }
        }
        w.write_all(&(self.by_value.len() as u64).to_le_bytes())?;
        let mut buf = Vec::with_capacity(16 * 4096);
        for chunk in self.by_value.chunks(4096) {
            buf.clear();
            for &(value, location) in chunk {
                buf.extend_from_slice(&(value as u64).to_le_bytes());
                buf.extend_from_slice(&(location as u64).to_le_bytes());
            }
            w.write_all(&buf)?;
        }
        Ok(())
    }

    pub fn read_from(mut r: impl Read) -> io::Result<PointerMap> {
        let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_owned());
        let mut magic = [0; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid("not a procodile pointer map"));
        }
        if read_u32(&mut r)? != VERSION {
            return Err(invalid("unsupported pointer map version"));
        }
        let width = read_u32(&mut r)? as usize;
        if width != 4 && width != 8 {
            return Err(invalid("invalid pointer width"));
        }
        let module_count = read_len(&mut r, 1 << 16)?;
        let mut modules = Vec::with_capacity(module_count);
        for _ in 0..module_count {
            let mut name = vec![0; read_len(&mut r, 1 << 16)?];
            r.read_exact(&mut name)?;
            let name = String::from_utf8(name).map_err(|_| invalid("invalid module name"))?;
            let [base, start, end] = [
                read_usize(&mut r)?,
                read_usize(&mut r)?,
                read_usize(&mut r)?,
            ];
            modules.push(MapModule {
                name,
                base: Address::new(base),
                statics: Address::new(start)..Address::new(end),
            });
        }
        let count = read_len(&mut r, usize::MAX / 16)?;
        let mut by_value = Vec::with_capacity(count.min(1 << 24));
        for _ in 0..count {
            by_value.push((read_usize(&mut r)?, read_usize(&mut r)?));
        }
        Ok(Self::from_parts(width, modules, by_value))
    }

    fn find_static(&self, address: usize) -> Option<usize> {
        let i = self
            .modules
            .partition_point(|m| m.statics.start.get() <= address);
        let module = self.modules.get(i.checked_sub(1)?)?;
        module
            .statics
            .contains(&Address::new(address))
            .then_some(i - 1)
    }
}

/// Builds a pointer map of `handle` and scans it for paths to `target`, shortest first.
pub fn scan_pointers(
    handle: &ProcessHandle,
    target: Address,
    map_options: &PointerMapOptions,
    options: &PointerScanOptions,
    progress: Option<&Progress>,
) -> Result<Vec<PointerPath>> {
    if options.max_depth == 0 {
        return Err(Error::InvalidScan("max depth must be at least 1".into()));
    }
    Ok(PointerMap::build(handle, map_options, progress)?.scan(target, options))
}

/// Keeps the paths that currently resolve to `target`, e.g. after the process restarted
/// and the value was found again at a new address.
pub fn filter_pointers(
    handle: &ProcessHandle,
    paths: &[PointerPath],
    target: Address,
) -> Result<Vec<PointerPath>> {
    let modules = handle.modules()?;
    let width = handle.pointer_width()?;
    Ok(paths
        .iter()
        .filter(|p| {
            p.resolve(handle, &modules, width)
                .is_ok_and(|a| a == target)
        })
        .cloned()
        .collect())
}

fn read_word(raw: &[u8]) -> usize {
    match raw.len() {
        4 => u32::from_ne_bytes(raw.try_into().unwrap()) as usize,
        _ => usize::from_ne_bytes(raw.try_into().unwrap()),
    }
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_usize(r: &mut impl Read) -> io::Result<usize> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    usize::try_from(u64::from_le_bytes(b))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "address out of range"))
}

fn read_len(r: &mut impl Read, max: usize) -> io::Result<usize> {
    let n = read_usize(r)?;
    if n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "length out of range",
        ));
    }
    Ok(n)
}

fn is_valid(valid: &[Range<usize>], value: usize) -> bool {
    let i = valid.partition_point(|r| r.start <= value);
    i > 0 && valid[i - 1].contains(&value)
}

/// The backwards search, as a DAG: each edge goes from a pointer's location to the address
/// it points into, one level closer to the target.
struct Graph {
    /// location -> [(address it leads to, offset added)]
    edges: HashMap<usize, Vec<(usize, usize)>>,
    /// Static locations, with their module index, shallowest first.
    roots: Vec<(usize, usize)>,
}

fn walk_back(map: &PointerMap, target: usize, options: &PointerScanOptions) -> Graph {
    let mut depth: HashMap<usize, usize> = HashMap::from([(target, 0)]);
    let mut edges: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    let mut roots = Vec::new();
    let mut frontier = vec![target];

    for level in 1..=options.max_depth {
        let mut next = Vec::new();
        for &address in &frontier {
            let low = address.saturating_sub(options.max_offset);
            let pointers = &map.by_value;
            let start = pointers.partition_point(|&(value, _)| value < low);
            for &(value, location) in pointers[start..].iter().take_while(|(v, _)| *v <= address) {
                match depth.get(&location) {
                    // Only link to the next level, so the graph has no cycles and every
                    // path from a root reaches the target in exactly `level` steps.
                    Some(&d) if d != level => continue,
                    Some(_) => {}
                    None => {
                        if depth.len() >= MAX_NODES {
                            continue;
                        }
                        depth.insert(location, level);
                        match map.find_static(location) {
                            Some(module) => roots.push((location, module)),
                            None => next.push(location),
                        }
                    }
                }
                edges
                    .entry(location)
                    .or_default()
                    .push((address, address - value));
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    Graph { edges, roots }
}

/// Depth-first enumeration of the offsets from `node` down to `target`. `emit` returns
/// false to stop.
fn collect_paths(
    graph: &Graph,
    node: usize,
    target: usize,
    offsets: &mut Vec<usize>,
    emit: &mut dyn FnMut(&[usize]) -> bool,
) -> bool {
    if node == target && !offsets.is_empty() {
        return emit(offsets);
    }
    for &(next, offset) in graph.edges.get(&node).into_iter().flatten() {
        offsets.push(offset);
        let keep_going = collect_paths(graph, next, target, offsets, emit);
        offsets.pop();
        if !keep_going {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicPtr, Ordering};

    use super::*;

    #[repr(C)]
    struct Player {
        _pad: [u64; 3],
        stats: Box<Stats>,
    }

    #[repr(C)]
    struct Stats {
        _pad: [u32; 5],
        health: u32,
    }

    /// Zero-initialized, so on Linux it lands in `.bss` after the image mappings.
    static PLAYER: AtomicPtr<Player> = AtomicPtr::new(std::ptr::null_mut());

    #[test]
    fn finds_static_path_to_heap_value() {
        let player = Box::into_raw(Box::new(Player {
            _pad: [0; 3],
            stats: Box::new(Stats {
                _pad: [0; 5],
                health: 1337,
            }),
        }));
        PLAYER.store(player, Ordering::SeqCst);
        let health = unsafe { &raw const (*player).stats.health };
        let target = Address::new(health as usize);

        let handle = ProcessHandle::open_current().unwrap();
        let options = PointerScanOptions {
            max_depth: 3,
            max_offset: 0x100,
            ..Default::default()
        };
        let paths = scan_pointers(&handle, target, &Default::default(), &options, None).unwrap();

        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy();
        let modules = handle.modules().unwrap();
        let module = modules
            .iter()
            .find(|m| m.name.to_string_lossy() == exe)
            .unwrap();
        let expected = PointerPath {
            module: exe.into_owned(),
            module_offset: &raw const PLAYER as usize - module.base.get(),
            offsets: vec![
                std::mem::offset_of!(Player, stats),
                std::mem::offset_of!(Stats, health),
            ],
        };
        assert!(
            paths.contains(&expected),
            "{expected} not in {} paths",
            paths.len()
        );

        // Other paths may already be stale: parallel tests keep allocating, which moves
        // pointers such as malloc's arena top. Filtering is how those get weeded out.
        let width = handle.pointer_width().unwrap();
        assert_eq!(expected.resolve(&handle, &modules, width).unwrap(), target);
        assert!(
            filter_pointers(&handle, &paths, target)
                .unwrap()
                .contains(&expected)
        );
        assert!(
            !filter_pointers(&handle, &paths, target + 4)
                .unwrap()
                .contains(&expected)
        );

        drop(unsafe { Box::from_raw(PLAYER.swap(std::ptr::null_mut(), Ordering::SeqCst)) });
    }

    static SAVE: AtomicPtr<Player> = AtomicPtr::new(std::ptr::null_mut());

    #[test]
    fn saved_maps_intersect_across_restarts() {
        let new_stats = |health| {
            Box::new(Stats {
                _pad: [0; 5],
                health,
            })
        };
        let player = Box::into_raw(Box::new(Player {
            _pad: [0; 3],
            stats: new_stats(10),
        }));
        SAVE.store(player, Ordering::SeqCst);
        let target =
            |p: *mut Player| Address::new(unsafe { &raw const (*p).stats.health } as usize);

        let handle = ProcessHandle::open_current().unwrap();
        let first_target = target(player);
        let first = PointerMap::build(&handle, &Default::default(), None).unwrap();

        // Round-trip through the binary format.
        let mut bytes = Vec::new();
        first.write_to(&mut bytes).unwrap();
        let first = PointerMap::read_from(bytes.as_slice()).unwrap();

        let options = PointerScanOptions {
            max_depth: 2,
            max_offset: 0x100,
            ..Default::default()
        };
        let paths = first.scan(first_target, &options);
        assert!(paths.iter().all(|p| first.resolve(p) == Some(first_target)));

        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy().into_owned();
        let module = first.modules().iter().find(|m| m.name == exe).unwrap();
        let expected = PointerPath {
            module: exe,
            module_offset: &raw const SAVE as usize - module.base.get(),
            offsets: vec![
                std::mem::offset_of!(Player, stats),
                std::mem::offset_of!(Stats, health),
            ],
        };
        assert!(paths.contains(&expected));

        // "Restart": the value moves to a new allocation, and a second map is taken.
        unsafe { (*player).stats = new_stats(10) };
        let second_target = target(player);
        assert_ne!(first_target, second_target);
        let second = PointerMap::build(&handle, &Default::default(), None).unwrap();

        let kept = second.filter(&paths, second_target);
        assert!(kept.contains(&expected));
        assert!(kept.len() <= paths.len());
        assert!(
            second
                .filter(&paths, first_target)
                .iter()
                .all(|p| p != &expected)
        );

        drop(unsafe { Box::from_raw(SAVE.swap(std::ptr::null_mut(), Ordering::SeqCst)) });
    }

    #[test]
    fn rejects_bad_map_data() {
        assert!(PointerMap::read_from(&b"not a map"[..]).is_err());
        let map = PointerMap::from_parts(8, Vec::new(), vec![(1, 2)]);
        let mut bytes = Vec::new();
        map.write_to(&mut bytes).unwrap();
        assert_eq!(PointerMap::read_from(bytes.as_slice()).unwrap(), map);
        assert!(PointerMap::read_from(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn resolving_garbage_does_not_overflow() {
        static HIGH: usize = usize::MAX - 4;
        let handle = ProcessHandle::open_current().unwrap();
        let modules = handle.modules().unwrap();
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy().into_owned();
        let module = modules
            .iter()
            .find(|m| m.name.to_string_lossy() == exe)
            .unwrap();
        let path = PointerPath {
            module: exe,
            module_offset: &raw const HIGH as usize - module.base.get(),
            offsets: vec![0x100],
        };
        let width = handle.pointer_width().unwrap();
        assert!(path.resolve(&handle, &modules, width).is_err());
    }

    #[test]
    fn path_display_round_trips() {
        let path = PointerPath {
            module: "game.exe".into(),
            module_offset: 0x1234,
            offsets: vec![0x10, 0x8],
        };
        assert_eq!(path.to_string(), "[[game.exe+0x1234]+0x10]+0x8");
        assert_eq!(path.to_string().parse::<PointerPath>().unwrap(), path);

        let quoted = PointerPath {
            module: "ld-linux-x86-64.so.2".into(),
            module_offset: 0,
            offsets: vec![0],
        };
        assert_eq!(quoted.to_string(), "[\"ld-linux-x86-64.so.2\"+0x0]+0x0");
        assert_eq!(quoted.to_string().parse::<PointerPath>().unwrap(), quoted);

        assert!("[game.exe+0x10".parse::<PointerPath>().is_err());
        assert!("game.exe".parse::<PointerPath>().is_err());
    }
}
