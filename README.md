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
| `table add/list/write/freeze/unfreeze/remove/save/load` | the address table |

Aliases: `x` (memory read), `attach`, `detach`, `c` (process continue), `ps`, `q`.

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
