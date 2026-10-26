# procodile

Cross-platform (Linux and Windows) primitives for reading and modifying the memory of
other processes: everything a tool like Cheat Engine is built from.

- Processes: list, find by name, open, suspend/resume, query pointer width.
- Memory: safe typed reads and writes, regions with protection and kind, protect,
  allocate and free (Windows).
- Modules: loaded images with base and size.
- Scanning: first/next value scans (exact, ranges, changed, increased, unknown initial
  value, ...), array-of-bytes patterns, and pointer scans with saveable pointer maps.
- Structs: Rust-syntax struct definitions, read from memory as a tree of named fields.
- Freezing: hold values in place from a background thread.

For an interactive tool built on this crate, see
[procodile-cli](https://crates.io/crates/procodile-cli).

```sh
cargo add procodile
```

## Permissions

- **Linux:** opening another process's memory (`/proc/<pid>/mem`) needs ptrace
  permission. Either run as root, grant `CAP_SYS_PTRACE`, or set
  `/proc/sys/kernel/yama/ptrace_scope` to `0`. The default (`1`) only allows your own child
  processes, unless the target opts in with `prctl(PR_SET_PTRACER, ...)`.
- **Windows:** protected processes need an elevated (Administrator) prompt.

[`Error::is_permission_denied`] tells these failures apart from others.

## Processes and memory

```rust,no_run
use procodile::{Access, Address, Process};

# fn main() -> procodile::Result<()> {
let game = Process::by_name("game.exe")?.next().expect("not running");
let handle = game.open(Access::ReadWrite)?;

let health_at = Address::new(0x7ff6_1234_5678);
let health: i32 = handle.read(health_at)?;
handle.write(health_at, &(health + 100))?;

// Raw bytes; `read_bytes` reports short reads instead of failing.
let mut buf = [0u8; 64];
let n = handle.read_bytes(health_at, &mut buf)?;
# let _ = n;
# Ok(())
# }
```

[`ProcessHandle::read`] works for any [`Pod`] type: integers, floats, arrays of them, and
your own `#[repr(C)]` structs if you implement the (unsafe) trait for them. Handles are
`Send + Sync`, so one can be shared between threads behind an `Arc`.

## Regions and modules

```rust,no_run
# fn main() -> procodile::Result<()> {
# let handle = procodile::ProcessHandle::open_current()?;
for region in handle.regions()? {
    if region.protection.readable() && region.protection.writable() {
        println!("{:?}..{:?} {} {:?}", region.base, region.end(), region.protection, region.kind);
    }
}

let exe = handle.module("game.exe")?.expect("module");
println!("game.exe is at {:?} ({:#x} bytes)", exe.base, exe.size);
# Ok(())
# }
```

## Value scanning

A first scan finds every matching value; next scans narrow the results by comparing
against what each address held last time.

```rust,no_run
use procodile::scan::{Compare, Scan, ScanOptions, Value, ValueType};

# fn main() -> procodile::Result<()> {
# let handle = procodile::ProcessHandle::open_current()?;
let options = ScanOptions::new(ValueType::I32);
let mut scan = Scan::first(&handle, options, Compare::Exact(Value::I32(100)), None)?;

// ...the value changes in the game...
scan.next(&handle, Compare::Decreased, None)?;

for m in scan.results().take(10) {
    println!("{:?} was {}", m.address, m.value);
}
# Ok(())
# }
```

Pass a [`scan::Progress`] to watch progress or cancel from another thread. Use
`Compare::Unknown` for an unknown initial value: the first scan then keeps a snapshot of
memory, and relative next scans (`Changed`, `Increased`, ...) narrow it down.

## Byte patterns

```rust,no_run
use procodile::scan::{Pattern, PatternOptions, find_pattern};

# fn main() -> procodile::Result<()> {
# let handle = procodile::ProcessHandle::open_current()?;
let pattern: Pattern = "48 8b 05 ?? ?? ?? ?? 48 85 c0".parse().unwrap();
let options = PatternOptions {
    executable_only: true,
    ..Default::default()
};
let hits = find_pattern(&handle, &pattern, &options, None)?;
# let _ = hits;
# Ok(())
# }
```

## Pointer scanning

Heap addresses change every run. A pointer scan finds paths from module statics to a
value, such as `[[game.exe+0x5e068]+0x18]+0x0`, which keep working after a restart.

```rust,no_run
use procodile::Address;
use procodile::scan::{PointerMap, PointerScanOptions};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let handle = procodile::ProcessHandle::open_current()?;
# let value_address = Address::new(0);
let map = PointerMap::build(&handle, &Default::default(), None)?;
let paths = map.scan(value_address, &PointerScanOptions::default());

// Save the map, and after a restart, keep only paths that still lead to the value.
map.write_to(std::fs::File::create("run1.pmap")?)?;
# let new_address = Address::new(0);
let still_valid = procodile::scan::filter_pointers(&handle, &paths, new_address)?;
# let _ = still_valid;
# Ok(())
# }
```

A [`scan::PointerMap`] can be scanned, resolve paths and filter them offline, so maps
saved from several runs can be intersected later. That is the most reliable way to find
paths that survive restarts.

## Structs

Describe data with Rust struct syntax and read it as named fields. Layout follows
`#[repr(C)]` rules for the target's pointer size; `#[offset(N)]` pins a field.

```rust,no_run
use procodile::Address;
use procodile::structs::{Node, Structs};

# fn main() -> procodile::Result<()> {
# let handle = procodile::ProcessHandle::open_current()?;
let mut structs = Structs::new();
structs
    .define(
        "struct Stats { health: i32, armor: i32 }
         struct Player {
             name: *const c_char,
             stats: *const Stats,
             #[offset(0x40)]
             pos: [f32; 3],
         }",
    )
    .unwrap();

let width = handle.pointer_width()?;
let player = structs.read(&handle, "Player", Address::new(0x1000), width, 1)?;
if let Node::Struct { fields, .. } = player {
    for field in fields {
        println!("{} @ {:#x}: {:?}", field.name, field.offset, field.value);
    }
}
# Ok(())
# }
```

[`structs::dissect`] guesses the fields of memory you have no definition for yet.

## Freezing

```rust,no_run
use std::sync::Arc;
use procodile::Address;
use procodile::freeze::Freezer;

# fn main() -> procodile::Result<()> {
# let handle = procodile::ProcessHandle::open_current()?;
let freezer = Freezer::new(Arc::new(handle));
let id = freezer.freeze(Address::new(0x1000), 999i32.to_ne_bytes().to_vec());
// ...
freezer.unfreeze(id);
# Ok(())
# }
```

## Platform support

| | Linux | Windows |
| --- | --- | --- |
| Processes, memory, regions, modules, scans | yes | yes |
| Suspend / resume | `SIGSTOP` / `SIGCONT` | `NtSuspendProcess` |
| Protect, allocate, free | no ([`Error::Unsupported`]) | yes |

Like the standard library, the crate is split into platform-independent modules over a
private `sys` backend per OS. Things that only exist on one platform are extension traits
in [`os`], such as raw file descriptor and handle access, or the Windows working set.

## License

MIT OR Apache-2.0.

[`Error::is_permission_denied`]: https://docs.rs/procodile/latest/procodile/error/enum.Error.html#method.is_permission_denied
[`Error::Unsupported`]: https://docs.rs/procodile/latest/procodile/error/enum.Error.html#variant.Unsupported
[`ProcessHandle::read`]: https://docs.rs/procodile/latest/procodile/process/struct.ProcessHandle.html#method.read
[`Pod`]: https://docs.rs/procodile/latest/procodile/memory/trait.Pod.html
[`scan::Progress`]: https://docs.rs/procodile/latest/procodile/scan/struct.Progress.html
[`scan::PointerMap`]: https://docs.rs/procodile/latest/procodile/scan/struct.PointerMap.html
[`structs::dissect`]: https://docs.rs/procodile/latest/procodile/structs/fn.dissect.html
[`os`]: https://docs.rs/procodile/latest/procodile/os/index.html
