//! Cheat Engine-style value scanning: a first scan over all matching memory, then any number
//! of next scans that narrow the candidates by comparing against their previous values.

/// Runs `$body` with `$T` bound to the primitive type for a [`ValueType`].
macro_rules! with_scalar {
    ($ty:expr, $T:ident => $body:expr) => {
        match $ty {
            $crate::scan::ValueType::I8 => {
                type $T = i8;
                $body
            }
            $crate::scan::ValueType::U8 => {
                type $T = u8;
                $body
            }
            $crate::scan::ValueType::I16 => {
                type $T = i16;
                $body
            }
            $crate::scan::ValueType::U16 => {
                type $T = u16;
                $body
            }
            $crate::scan::ValueType::I32 => {
                type $T = i32;
                $body
            }
            $crate::scan::ValueType::U32 => {
                type $T = u32;
                $body
            }
            $crate::scan::ValueType::I64 => {
                type $T = i64;
                $body
            }
            $crate::scan::ValueType::U64 => {
                type $T = u64;
                $body
            }
            $crate::scan::ValueType::F32 => {
                type $T = f32;
                $body
            }
            $crate::scan::ValueType::F64 => {
                type $T = f64;
                $body
            }
        }
    };
}

mod pattern;
mod pointer;
mod value;

use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;

pub use pattern::{ParsePatternError, Pattern, PatternOptions, find_pattern};
pub use pointer::{
    MapModule, PointerMap, PointerMapOptions, PointerPath, PointerScanOptions, filter_pointers,
    scan_pointers,
};
use value::Scalar;
pub use value::{ParseValueError, Value, ValueType};

use crate::{Address, Error, ProcessHandle, Region, RegionKind, Result};

/// Bytes of candidate positions handled per work item in a first scan.
const CHUNK_SIZE: usize = 1 << 20;
/// Largest span of memory read at once when re-reading matches in a next scan.
const MAX_SPAN: usize = 64 << 10;

/// How a value is tested against the scan's value, or against its own previous value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Compare {
    Exact(Value),
    NotEqual(Value),
    GreaterThan(Value),
    LessThan(Value),
    /// Inclusive on both ends.
    Between(Value, Value),
    /// First scan only: keep everything, to be narrowed by relative next scans.
    Unknown,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy(Value),
    DecreasedBy(Value),
}

impl Compare {
    /// Whether this compares against a previous value, and so is only valid in a next scan.
    pub fn is_relative(&self) -> bool {
        matches!(
            self,
            Self::Changed
                | Self::Unchanged
                | Self::Increased
                | Self::Decreased
                | Self::IncreasedBy(_)
                | Self::DecreasedBy(_)
        )
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub value_type: ValueType,
    /// Only consider addresses that are a multiple of this. `0` means the type's size,
    /// which is what compilers almost always use (Cheat Engine's "fast scan").
    pub alignment: usize,
    /// Skip read-only memory. Values worth changing are almost always writable.
    pub writable_only: bool,
    /// Also scan shared and file mappings, not just private memory and images.
    pub include_mapped: bool,
    /// Restrict the scan to this address range.
    pub range: Option<Range<Address>>,
    /// Floats within this distance of the target count as equal.
    pub float_tolerance: f64,
    /// Worker threads; `0` means one per available CPU.
    pub threads: usize,
}

impl ScanOptions {
    pub fn new(value_type: ValueType) -> Self {
        Self {
            value_type,
            alignment: 0,
            writable_only: true,
            include_mapped: false,
            range: None,
            float_tolerance: 0.0,
            threads: 0,
        }
    }

    fn alignment(&self) -> usize {
        match self.alignment {
            0 => self.value_type.size(),
            n => n,
        }
    }

    fn threads(&self) -> usize {
        match self.threads {
            0 => thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        }
    }
}

/// Shared progress and cancellation for a running scan, safe to poll from another thread.
///
/// Cancellation is sticky: use a fresh `Progress` for each scan.
#[derive(Debug, Default)]
pub struct Progress {
    done: AtomicU64,
    total: AtomicU64,
    cancelled: AtomicBool,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes processed so far.
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    /// Bytes the current scan will process.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn fraction(&self) -> f64 {
        match self.total() {
            0 => 0.0,
            total => self.done() as f64 / total as f64,
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn start(&self, total: u64) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    fn advance(&self, bytes: usize) {
        self.done.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// One scan result: an address and the value it had at the last scan.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Match {
    pub address: Address,
    pub value: Value,
}

/// The state of a scan between steps.
pub struct Scan {
    options: ScanOptions,
    state: State,
}

enum State {
    /// After an unknown-initial-value first scan: raw copies of memory, so no per-address
    /// storage is needed until a relative next scan narrows things down.
    Snapshot(Vec<Snapshot>),
    /// Sorted addresses, with their last values packed as `value_type.size()` bytes each.
    Matches {
        addresses: Vec<Address>,
        values: Vec<u8>,
    },
}

struct Snapshot {
    base: Address,
    /// Candidate positions are offsets below this; the bytes after it only exist so values
    /// straddling the chunk boundary can be read.
    positions: usize,
    bytes: Vec<u8>,
}

struct Chunk {
    base: Address,
    positions: usize,
    /// Bytes to read: `positions` plus room for a value straddling the end.
    len: usize,
}

impl Scan {
    pub fn first(
        handle: &ProcessHandle,
        options: ScanOptions,
        compare: Compare,
        progress: Option<&Progress>,
    ) -> Result<Scan> {
        if compare.is_relative() {
            return Err(Error::InvalidScan(
                "a first scan has no previous values to compare against".into(),
            ));
        }
        let chunks = chunks(handle, &options)?;
        let progress_or_default = Progress::new();
        let progress = progress.unwrap_or(&progress_or_default);
        progress.start(chunks.iter().map(|c| c.positions as u64).sum());

        let ty = options.value_type;
        let state = if compare == Compare::Unknown {
            let snapshots = par_map(&chunks, options.threads(), |chunk| {
                if progress.is_cancelled() {
                    return None;
                }
                let mut bytes = vec![0; chunk.len];
                let read = handle.read_bytes(chunk.base, &mut bytes).unwrap_or(0);
                bytes.truncate(read);
                progress.advance(chunk.positions);
                (read >= ty.size()).then(|| Snapshot {
                    base: chunk.base,
                    positions: chunk.positions.min(read),
                    bytes,
                })
            });
            State::Snapshot(snapshots.into_iter().flatten().collect())
        } else {
            with_scalar!(ty, T => {
                let cmp = Cmp::<T>::compile(compare)?;
                let parts = par_map(&chunks, options.threads(), |chunk| {
                    let mut out = (Vec::new(), Vec::new());
                    if progress.is_cancelled() {
                        return out;
                    }
                    let mut bytes = vec![0; chunk.len];
                    let read = handle.read_bytes(chunk.base, &mut bytes).unwrap_or(0);
                    scan_fresh(
                        &cmp,
                        &options,
                        chunk.base,
                        &bytes[..read],
                        chunk.positions,
                        &mut out,
                    );
                    progress.advance(chunk.positions);
                    out
                });
                collect_matches(parts)
            })
        };

        if progress.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(Scan { options, state })
    }

    /// Narrows the results by re-reading each candidate. On error or cancellation the
    /// previous results are kept.
    pub fn next(
        &mut self,
        handle: &ProcessHandle,
        compare: Compare,
        progress: Option<&Progress>,
    ) -> Result<()> {
        if compare == Compare::Unknown {
            return Err(Error::InvalidScan(
                "an unknown value can only be used in a first scan".into(),
            ));
        }
        let progress_or_default = Progress::new();
        let progress = progress.unwrap_or(&progress_or_default);
        let options = &self.options;
        let ty = options.value_type;

        let state = with_scalar!(ty, T => {
            let cmp = Cmp::<T>::compile(compare)?;
            match &self.state {
                State::Snapshot(snapshots) => {
                    progress.start(snapshots.iter().map(|s| s.positions as u64).sum());
                    let parts = par_map(snapshots, options.threads(), |snap| {
                        let mut out = (Vec::new(), Vec::new());
                        if progress.is_cancelled() {
                            return out;
                        }
                        let mut bytes = vec![0; snap.bytes.len()];
                        let read = handle.read_bytes(snap.base, &mut bytes).unwrap_or(0);
                        scan_against_snapshot(&cmp, options, snap, &bytes[..read], &mut out);
                        progress.advance(snap.positions);
                        out
                    });
                    collect_matches(parts)
                }
                State::Matches { addresses, values } => {
                    let spans = spans(addresses, ty.size());
                    progress.start(addresses.len() as u64);
                    let parts = par_map(&spans, options.threads(), |span| {
                        let mut out = (Vec::new(), Vec::new());
                        if progress.is_cancelled() {
                            return out;
                        }
                        rescan_span(&cmp, options, handle, addresses, values, span.clone(), &mut out);
                        progress.advance(span.len());
                        out
                    });
                    collect_matches(parts)
                }
            }
        });

        if progress.is_cancelled() {
            return Err(Error::Cancelled);
        }
        self.state = state;
        Ok(())
    }

    pub fn options(&self) -> &ScanOptions {
        &self.options
    }

    pub fn value_type(&self) -> ValueType {
        self.options.value_type
    }

    /// Number of candidate addresses.
    pub fn len(&self) -> usize {
        match &self.state {
            State::Matches { addresses, .. } => addresses.len(),
            State::Snapshot(snapshots) => {
                let align = self.options.alignment();
                snapshots
                    .iter()
                    .map(|s| {
                        positions(
                            s.base,
                            s.positions,
                            s.bytes.len(),
                            self.value_type().size(),
                            align,
                        )
                        .len()
                    })
                    .sum()
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this is still an unnarrowed unknown-value snapshot. Listing the results of
    /// a snapshot works but yields every aligned address in scanned memory.
    pub fn is_snapshot(&self) -> bool {
        matches!(self.state, State::Snapshot(_))
    }

    /// The candidates in address order, with the values they had at the last scan.
    pub fn results(&self) -> Box<dyn Iterator<Item = Match> + '_> {
        let ty = self.value_type();
        let size = ty.size();
        match &self.state {
            State::Matches { addresses, values } => {
                Box::new(addresses.iter().zip(values.chunks_exact(size)).map(
                    move |(&address, bytes)| Match {
                        address,
                        value: ty.decode(bytes),
                    },
                ))
            }
            State::Snapshot(snapshots) => {
                let align = self.options.alignment();
                Box::new(snapshots.iter().flat_map(move |s| {
                    positions(s.base, s.positions, s.bytes.len(), size, align).map(move |off| {
                        Match {
                            address: s.base + off,
                            value: ty.decode(&s.bytes[off..off + size]),
                        }
                    })
                }))
            }
        }
    }
}

/// `Compare` resolved for one primitive type.
#[derive(Clone, Copy)]
enum Cmp<T> {
    Eq(T),
    Ne(T),
    Gt(T),
    Lt(T),
    Between(T, T),
    Any,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy(T),
    DecreasedBy(T),
}

impl<T: Scalar> Cmp<T> {
    fn compile(compare: Compare) -> Result<Self> {
        let v = |value: Value| {
            T::from_value(value).ok_or_else(|| {
                Error::InvalidScan(format!(
                    "value {value} is a {}, but the scan is for {}",
                    value.ty(),
                    std::any::type_name::<T>()
                ))
            })
        };
        Ok(match compare {
            Compare::Exact(x) => Cmp::Eq(v(x)?),
            Compare::NotEqual(x) => Cmp::Ne(v(x)?),
            Compare::GreaterThan(x) => Cmp::Gt(v(x)?),
            Compare::LessThan(x) => Cmp::Lt(v(x)?),
            Compare::Between(a, b) => Cmp::Between(v(a)?, v(b)?),
            Compare::Unknown => Cmp::Any,
            Compare::Changed => Cmp::Changed,
            Compare::Unchanged => Cmp::Unchanged,
            Compare::Increased => Cmp::Increased,
            Compare::Decreased => Cmp::Decreased,
            Compare::IncreasedBy(x) => Cmp::IncreasedBy(v(x)?),
            Compare::DecreasedBy(x) => Cmp::DecreasedBy(v(x)?),
        })
    }

    /// `old` is ignored by absolute comparisons.
    #[inline(always)]
    fn test(&self, new: T, old: T, tolerance: f64) -> bool {
        match *self {
            Cmp::Eq(x) => new.approx_eq(x, tolerance),
            Cmp::Ne(x) => !new.approx_eq(x, tolerance),
            Cmp::Gt(x) => new > x,
            Cmp::Lt(x) => new < x,
            Cmp::Between(a, b) => a <= new && new <= b,
            Cmp::Any => true,
            Cmp::Changed => !new.approx_eq(old, tolerance),
            Cmp::Unchanged => new.approx_eq(old, tolerance),
            Cmp::Increased => new > old,
            Cmp::Decreased => new < old,
            Cmp::IncreasedBy(d) => new.approx_eq(old.wrapping_add(d), tolerance),
            Cmp::DecreasedBy(d) => old.approx_eq(new.wrapping_add(d), tolerance),
        }
    }
}

type MatchBuf = (Vec<Address>, Vec<u8>);

/// Aligned offsets in a buffer starting at `base` where a value may start: below
/// `positions`, and with the whole value inside `len` bytes.
fn positions(
    base: Address,
    positions: usize,
    len: usize,
    size: usize,
    align: usize,
) -> std::iter::StepBy<Range<usize>> {
    let first = (align - base.get() % align) % align;
    let end = positions.min((len + 1).saturating_sub(size));
    (first..end.max(first)).step_by(align)
}

fn push_match(out: &mut MatchBuf, address: Address, bytes: &[u8]) {
    out.0.push(address);
    out.1.extend_from_slice(bytes);
}

fn scan_fresh<T: Scalar>(
    cmp: &Cmp<T>,
    options: &ScanOptions,
    base: Address,
    bytes: &[u8],
    limit: usize,
    out: &mut MatchBuf,
) {
    let size = size_of::<T>();
    for off in positions(base, limit, bytes.len(), size, options.alignment()) {
        let value = &bytes[off..off + size];
        let v = T::read(value);
        if cmp.test(v, v, options.float_tolerance) {
            push_match(out, base + off, value);
        }
    }
}

fn scan_against_snapshot<T: Scalar>(
    cmp: &Cmp<T>,
    options: &ScanOptions,
    snap: &Snapshot,
    bytes: &[u8],
    out: &mut MatchBuf,
) {
    let size = size_of::<T>();
    let len = bytes.len().min(snap.bytes.len());
    for off in positions(snap.base, snap.positions, len, size, options.alignment()) {
        let value = &bytes[off..off + size];
        let new = T::read(value);
        let old = T::read(&snap.bytes[off..off + size]);
        if cmp.test(new, old, options.float_tolerance) {
            push_match(out, snap.base + off, value);
        }
    }
}

/// Groups sorted addresses into index ranges whose values fit in one read of `MAX_SPAN`.
fn spans(addresses: &[Address], size: usize) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut start = 0;
    for i in 1..=addresses.len() {
        if i == addresses.len() || addresses[i] + size - addresses[start] > MAX_SPAN {
            spans.push(start..i);
            start = i;
        }
    }
    spans
}

fn rescan_span<T: Scalar>(
    cmp: &Cmp<T>,
    options: &ScanOptions,
    handle: &ProcessHandle,
    addresses: &[Address],
    values: &[u8],
    span: Range<usize>,
    out: &mut MatchBuf,
) {
    let size = size_of::<T>();
    let base = addresses[span.start];
    let mut bytes = vec![0; addresses[span.end - 1] + size - base];
    // Memory that has been unmapped since the last scan drops out of the results.
    let read = handle.read_bytes(base, &mut bytes).unwrap_or(0);
    for i in span {
        let off = addresses[i] - base;
        if off + size > read {
            break;
        }
        let value = &bytes[off..off + size];
        let old = T::read(&values[i * size..]);
        if cmp.test(T::read(value), old, options.float_tolerance) {
            push_match(out, addresses[i], value);
        }
    }
}

fn collect_matches(parts: Vec<MatchBuf>) -> State {
    let count = parts.iter().map(|p| p.0.len()).sum();
    let mut addresses = Vec::with_capacity(count);
    let mut values = Vec::new();
    for (a, v) in parts {
        addresses.extend(a);
        values.extend(v);
    }
    State::Matches { addresses, values }
}

/// Splits the regions selected by `options` into work items.
fn chunks(handle: &ProcessHandle, options: &ScanOptions) -> Result<Vec<Chunk>> {
    chunks_where(
        handle,
        options.range.as_ref(),
        options.value_type.size(),
        |region| {
            (!options.writable_only || region.protection.writable())
                && (options.include_mapped || region.kind != RegionKind::Mapped)
        },
    )
}

/// Splits the readable regions accepted by `filter`, clipped to `range`, into work items
/// that can each hold a `value_len`-byte value starting at any of their positions.
fn chunks_where(
    handle: &ProcessHandle,
    range: Option<&Range<Address>>,
    value_len: usize,
    filter: impl Fn(&Region) -> bool,
) -> Result<Vec<Chunk>> {
    let mut chunks = Vec::new();
    for region in handle.regions()? {
        if !region.protection.readable() || !filter(&region) {
            continue;
        }
        let (mut start, mut end) = (region.base, region.end());
        if let Some(range) = range {
            start = start.max(range.start);
            end = end.min(range.end);
        }
        while start < end {
            let positions = CHUNK_SIZE.min(end - start);
            let len = (positions + value_len - 1).min(region.end() - start);
            chunks.push(Chunk {
                base: start,
                positions,
                len,
            });
            start += positions;
        }
    }
    Ok(chunks)
}

/// Maps `f` over `items` on up to `threads` scoped threads, keeping the input order.
fn par_map<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = threads.min(items.len());
    if threads <= 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let mut indexed: Vec<(usize, R)> = thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        out.push((i, f(item)));
                    }
                    out
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("scan worker panicked"))
            .collect()
    });
    indexed.sort_unstable_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, r)| r).collect()
}

#[cfg(test)]
mod tests;
