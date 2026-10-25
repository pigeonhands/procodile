//! Pointer scanning: finding chains of pointers from static memory to an address, so a
//! value can be found again after the process restarts and its heap moves.
//!
//! The scan builds a reverse map of every pointer in memory (value -> where it is stored),
//! then walks backwards from the target: anything pointing at most `max_offset` bytes below
//! the target is a candidate parent, and so on up to `max_depth` levels. Parents inside a
//! module are static bases, which end a path.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use super::{Progress, chunks_where, par_map};
use crate::{Address, Error, Module, ProcessHandle, RegionKind, Result};

/// Stop expanding once this many intermediate addresses have been reached, to bound memory
/// and time on dense heaps.
const MAX_NODES: usize = 4_000_000;

#[derive(Debug, Clone)]
pub struct PointerScanOptions {
    /// Maximum number of pointer dereferences in a path.
    pub max_depth: usize,
    /// Maximum offset added after each dereference (structure field offset).
    pub max_offset: usize,
    /// Stop after this many paths.
    pub max_results: usize,
    /// Only look for pointers stored in writable memory, where almost all data pointers
    /// live. Turning this off also searches read-only data such as `.data.rel.ro`.
    pub writable_only: bool,
    /// Worker threads for building the pointer map; `0` means one per CPU.
    pub threads: usize,
}

impl Default for PointerScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_offset: 0x1000,
            max_results: 10_000,
            writable_only: true,
            threads: 0,
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
        let mut address = module.base + self.module_offset;
        for &offset in &self.offsets {
            address = handle.read_pointer(address, pointer_width)? + offset;
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

/// A module's static data: its image, plus on Linux the anonymous `.bss` mapping that
/// directly follows it.
struct StaticRange {
    range: Range<usize>,
    module: usize,
}

/// Finds pointer paths from module statics to `target`, shortest first.
pub fn scan_pointers(
    handle: &ProcessHandle,
    target: Address,
    options: &PointerScanOptions,
    progress: Option<&Progress>,
) -> Result<Vec<PointerPath>> {
    if options.max_depth == 0 {
        return Err(Error::InvalidScan("max depth must be at least 1".into()));
    }
    let fallback = Progress::new();
    let progress = progress.unwrap_or(&fallback);
    let width = handle.pointer_width()?;
    let modules = handle.modules()?;
    let regions = handle.regions()?;

    let statics = static_ranges(&modules, &regions);
    let valid: Vec<Range<usize>> = regions
        .iter()
        .filter(|r| r.protection.readable())
        .map(|r| r.base.get()..r.end().get())
        .collect();

    let map = pointer_map(handle, options, width, &valid, progress)?;
    let graph = walk_back(&map, &statics, target.get(), options);

    let mut paths = Vec::new();
    for &(location, module) in &graph.roots {
        if paths.len() >= options.max_results {
            break;
        }
        let module = &modules[module];
        let mut offsets = Vec::new();
        collect_paths(
            &graph,
            location,
            target.get(),
            &mut offsets,
            &mut |offsets| {
                paths.push(PointerPath {
                    module: module.name.to_string_lossy().into_owned(),
                    module_offset: location - module.base.get(),
                    offsets: offsets.to_vec(),
                });
                paths.len() < options.max_results
            },
        );
    }
    paths.truncate(options.max_results);
    paths.sort_by_key(|p| (p.depth(), p.offsets.iter().sum::<usize>()));
    Ok(paths)
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

fn static_ranges(modules: &[Module], regions: &[crate::Region]) -> Vec<StaticRange> {
    let mut statics: Vec<StaticRange> = modules
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mut end = m.end();
            if let Some(bss) = regions
                .iter()
                .find(|r| r.base == end && r.kind == RegionKind::Private && r.path.is_none())
            {
                end = bss.end();
            }
            StaticRange {
                range: m.base.get()..end.get(),
                module: i,
            }
        })
        .collect();
    statics.sort_by_key(|s| s.range.start);
    statics
}

fn find_static(statics: &[StaticRange], address: usize) -> Option<usize> {
    let i = statics.partition_point(|s| s.range.start <= address);
    let s = statics.get(i.checked_sub(1)?)?;
    s.range.contains(&address).then_some(s.module)
}

fn is_valid(valid: &[Range<usize>], value: usize) -> bool {
    let i = valid.partition_point(|r| r.start <= value);
    i > 0 && valid[i - 1].contains(&value)
}

/// Every aligned pointer-sized value in scanned memory that points into a readable
/// region, as `(value, location)` sorted by value.
fn pointer_map(
    handle: &ProcessHandle,
    options: &PointerScanOptions,
    width: usize,
    valid: &[Range<usize>],
    progress: &Progress,
) -> Result<Vec<(usize, usize)>> {
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
            let raw = &bytes[off..off + width];
            let value = if width == 4 {
                u32::from_ne_bytes(raw.try_into().unwrap()) as usize
            } else {
                usize::from_ne_bytes(raw.try_into().unwrap())
            };
            if is_valid(valid, value) {
                out.push((value, base + off));
            }
        }
        progress.advance(chunk.positions);
        out
    });
    if progress.is_cancelled() {
        return Err(Error::Cancelled);
    }

    let mut map: Vec<(usize, usize)> = parts.into_iter().flatten().collect();
    map.sort_unstable();
    Ok(map)
}

/// The backwards search, as a DAG: each edge goes from a pointer's location to the address
/// it points into, one level closer to the target.
struct Graph {
    /// location -> [(address it leads to, offset added)]
    edges: HashMap<usize, Vec<(usize, usize)>>,
    /// Static locations, with their module index, shallowest first.
    roots: Vec<(usize, usize)>,
}

fn walk_back(
    map: &[(usize, usize)],
    statics: &[StaticRange],
    target: usize,
    options: &PointerScanOptions,
) -> Graph {
    let mut depth: HashMap<usize, usize> = HashMap::from([(target, 0)]);
    let mut edges: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    let mut roots = Vec::new();
    let mut frontier = vec![target];

    for level in 1..=options.max_depth {
        let mut next = Vec::new();
        for &address in &frontier {
            let low = address.saturating_sub(options.max_offset);
            let start = map.partition_point(|&(value, _)| value < low);
            for &(value, location) in map[start..].iter().take_while(|(v, _)| *v <= address) {
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
                        match find_static(statics, location) {
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
        let paths = scan_pointers(&handle, target, &options, None).unwrap();

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
