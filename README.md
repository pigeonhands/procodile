# procodile

Cross-platform (Linux and Windows) tools for reading and modifying the memory of other
processes: the building blocks of a Cheat Engine-style memory scanner, and an interactive
scanner built from them.

| Crate | | |
| --- | --- | --- |
| [`procodile`](procodile/README.md) | library | processes, memory, regions, modules, value / pattern / pointer scanning, structs, freezing |
| [`procodile-cli`](procodile-cli/README.md) | `procodile` binary | an lldb-style REPL and a TUI over the library |

```sh
cargo install procodile-cli     # the tool
cargo add procodile             # the library
```

```text
$ procodile -n game
(procodile) scan first 100
(procodile) scan next decreased
(procodile) table add #0 -d health
(procodile) table freeze $0 999
```

On Linux, attaching to another process needs ptrace permission (root, `CAP_SYS_PTRACE`,
or `kernel.yama.ptrace_scope = 0`); see the crate READMEs for details.

## Building from source

```sh
cargo build --release
cargo test --workspace
cargo run -p procodile --example target   # a toy process to practise on
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
