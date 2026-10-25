# procodile

A cross-platform (Linux and Windows) library for reading and modifying the memory of
other processes, with the primitives a tool like Cheat Engine needs, plus `procodile`, an
interactive frontend with an lldb-style REPL and a TUI.

- `procodile/`: the library. Processes, memory regions, modules, value scanning,
  array-of-bytes search, pointer scanning, value freezing.
- `procodile-cli/`: the `procodile` binary.

## Building

```sh
cargo build --release
./target/release/procodile
```

The CLI's `sqlite` feature (on by default) adds pointer databases. It bundles SQLite, so
it needs a C compiler; build with `--no-default-features` to leave it out.

### Permissions

- **Linux**: opening another process's memory needs ptrace permission. Either run as root,
  give the binary `CAP_SYS_PTRACE`, or set `/proc/sys/kernel/yama/ptrace_scope` to `0`.
  The default (`1`) only allows attaching to your own child processes.
- **Windows**: protected processes need an elevated (Administrator) prompt.

## Quick start

A toy target with a value behind a pointer chain is included:

```sh
cargo run -p procodile --example target   # prints its pid; Enter = take damage
```

In another terminal:

```text
$ procodile -n target
Process 4242 (target) attached
(procodile) scan first 100          # find every i32 equal to 100
6 results (0.05s); see `scan list`
                                    # ...take damage in the target...
(procodile) scan next decreased     # or `scan next 93`
1 result (0.05s); see `scan list`
(procodile) table add #0 -d health  # save scan result #0 as table entry $0
(procodile) table freeze $0 999     # keep it at 999
(procodile) x -t i32 $0             # memory read, lldb-style
```

Type `tui` at the prompt (or start with `procodile -o tui`) for the full-screen interface.

## The REPL

Commands follow lldb's `noun verb [options]` shape. Any unique prefix works (`mem re` is
`memory read`), an empty line repeats the previous command, Tab completes, and
`help <command>` describes any command.

| Command | What it does |
| --- | --- |
| `process list/attach/detach/status/interrupt/continue` | find and control processes |
| `memory read/write/region/find/protect/allocate/free` | inspect and change memory |
| `image list/lookup` | loaded modules |
| `scan first/next/list/reset` | value scanning |
| `pointer ...` | pointer scanning (below) |
| `struct define/load/save/list/show/read/dissect/remove` | structures (below) |
| `table add/list/write/freeze/unfreeze/remove/save/load` | the address table |

Aliases: `x` (memory read), `p` (struct read), `attach`, `detach`, `c` (process continue),
`ps`, `q`.

Startup options, as in lldb: `-p <pid>` / `-n <name>` to attach, `-o <command>` to run a
command first (repeatable), `-b` to exit afterwards.

### Address expressions

Anywhere an address is expected:

| Expression | Meaning |
| --- | --- |
| `0x7ffd1000`, `4096` | numbers: hex with `0x`, otherwise decimal |
| `libc.so.6+0x10` | module base plus offset (quote names with other characters: `"ld-linux-x86-64.so.2"`) |
| `[expr]` | the pointer stored at `expr` |
| `$N` | address table entry N |
| `#N` | value scan result N |
| `@N` | pointer scan result N |

## Structures

Define the layout of data in the target in a C-like syntax (so definitions can be pasted
from headers or reverse engineering tools), then view memory through it.

```c
// game.h
struct Stats {
    i32 armor;
    i32 mana;
    i32 health;
};

struct Player {
    u64 name_cap;
    char *name;          // char * and char[N] are shown as strings
    usize name_len;      // usize/size_t/uintptr_t follow the target's pointer size
    Stats *stats;
    u32 level;
    0x40: f32 pos[3];    // an explicit offset; the gap is padding
};
```

Fields use C's natural alignment, laid out for the target's pointer size. Types are the
Rust names (`i8`..`u64`, `f32`, `f64`, `bool`, `char`, `usize`, `isize`), fixed-size C
names (`int`, `unsigned short`, `uint32_t`, `float`, `double`, ...), pointers (including
`void *`), arrays, and other structs. `long` is rejected because its size differs between
Windows and Linux.

```text
(procodile) struct load game.h
loaded 2 structs from game.h
(procodile) struct show Player               # layout with offsets and sizes
/* offset | size */  struct Player {
/*    0x0 |  0x8 */      u64 name_cap;
/*    0x8 |  0x8 */      char *name;
...
(procodile) p Player [target+0x5e078]        # struct read, following pointers 1 level
(Player) 0x55f7353c4220 = {
  name_cap = 4
  name = 0x55f7353c6fc0 -> "hero"
  name_len = 4
  stats = 0x55f7353c6fe0 -> (Stats) {
    armor = 5
    mana = 50
    health = 100
  }
  level = 1
}
```

`struct read` takes `-d <depth>` (how many levels of pointers to follow; `0` shows
addresses only) and `-o` (show field offsets). `struct define '<source>'` defines
structures inline, and `struct save <file>` writes all definitions back out.

For memory you don't have a definition for yet, `struct dissect <addr> [-s size]` guesses
the fields: pointers into mapped memory, text, plausible floats, zeros and integers.
`-n <name>` also defines the guess as a structure (with fields named after their offsets)
to save, rename and refine.

In the TUI, select a scan result or table entry and press `v` to view it as a structure
instead of hex. The view updates live; `+`/`-` change the pointer depth and `[`/`]`
scroll. Press `v` and submit an empty name to go back to hex.

## Pointer scanning

A value scan finds where a value is *now*, but heap addresses change every time the
program restarts. A pointer scan finds **pointer paths** from static memory (inside a
module, so stable relative to its base) to the value, like
`[[game.exe+0x5e078]+0x18]+0x8`: read the pointer at `game.exe+0x5e078`, add `0x18`, read
the pointer there, add `0x8`. Paths can be used anywhere an address can, including in the
address table, where they keep working after a restart.

### One run: scan and filter

```text
(procodile) scan first 100
(procodile) scan next 93                  # narrow down until #0 is the value
(procodile) pointer scan #0               # find paths to it
2 pointer paths to 0x560e63f68fe8 (0.05s); see `pointer list`
(procodile) pointer list
@0     [[target+0x5e078]+0x18]+0x8  -> 0x560e63f68fe8
@1     [[target+0x5e078]+0x8]+0x28  -> 0x560e63f68fe8
(procodile) pointer save paths.txt
```

A scan usually finds many paths, and most only work by coincidence (they go through
temporary pointers). To weed them out, restart the target, find the value again, and keep
the paths that still lead to it:

```text
(procodile) pointer load paths.txt
(procodile) scan first 100 ...            # find the value in the new run
(procodile) pointer filter #0
1 of 2 paths resolve to 0x55efb7c11fe8
(procodile) table add @0 -d health        # stores the path itself
```

Options for `pointer scan`:

| Option | Default | |
| --- | --- | --- |
| `-d, --depth` | 4 | maximum number of dereferences |
| `-o, --max-offset` | 0x1000 | maximum offset after each dereference |
| `-c, --count` | 10000 | stop after this many paths |
| `--read-only` | off | also look for pointers stored in read-only memory |

Larger depths and offsets find more paths but take longer and produce more false ones.

### Several runs: pointer maps and a database

The more reliable workflow takes a **pointer map** (a snapshot of every pointer in the
process) on each run, recording where the value was in that run, and compares paths
across them offline. A pointer database keeps the maps and the results between
sessions:

```text
# run 1
(procodile) pointer open game.db          # created if missing
(procodile) scan first 100 ...            # find the value
(procodile) pointer map save #0 -l run1
saved pointer map 1: 1369 pointers, value at 0x560e63f68fe8

# restart the game, run 2
(procodile) pointer open game.db
(procodile) scan first 100 ...            # find it again
(procodile) pointer map save #0 -l run2

# compare, with or without the game running
(procodile) pointer map list
(procodile) pointer scan --map 1          # scan run 1's map offline
(procodile) pointer intersect 2           # keep paths that also work in run 2
map 2 (run2): 2 of 2 paths resolve to 0x560395745fe8
```

Save more maps and intersect with all of them (`pointer intersect 2 3 4`) until only the
reliable paths are left. Results are saved to the database whenever they change and
reloaded by `pointer open`, so a later session can pick up where you left off and
`table add @0` the survivors.

While a database is open, a live `pointer scan` also saves the map it built, so the first
run's map does not need a separate `pointer map save`.

| Command | What it does |
| --- | --- |
| `pointer scan <addr>` / `--map <id> [addr]` | find paths in the attached process / a saved map |
| `pointer list [-c N] [-s start]` | show paths and where they lead now |
| `pointer filter <addr>` | keep paths leading to `addr` in the attached process |
| `pointer intersect <id>...` | keep paths leading to each map's recorded address in that map |
| `pointer map save <addr> [-l label]` / `list` / `remove <id>` | manage saved maps |
| `pointer open <file>` / `close` | open or close a pointer database |
| `pointer save <file>` / `load <file>` | paths as a text file, one per line |
| `pointer reset` | discard the results |

### From the library

```rust
use procodile::scan::{PointerMap, PointerScanOptions};
use procodile::ProcessHandle;

let handle = ProcessHandle::open(pid, procodile::Access::Read)?;
let map = PointerMap::build(&handle, &Default::default(), None)?;
let paths = map.scan(value_address, &PointerScanOptions::default());

// Later, against a map from another run:
map.write_to(std::fs::File::create("run1.pmap")?)?;
let survivors = other_run_map.filter(&paths, value_address_in_other_run);
```
