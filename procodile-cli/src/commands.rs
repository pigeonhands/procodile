//! Runs parsed commands against a [`Session`] and prints the results, lldb-style.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use procodile::scan::{
    Compare, Pattern, PatternOptions, PointerPath, PointerScanOptions, Progress, Scan, ScanOptions,
    Value, ValueType, filter_pointers, find_pattern, scan_pointers,
};
use procodile::{Address, Module, Protection, Region};

use crate::cli::*;
use crate::format::{self, Format};
use crate::session::{PointerResults, Session};
use crate::table::Entry;

pub type CmdResult = Result<(), String>;

/// Set by the Ctrl-C handler while a command runs; long operations poll it to cancel.
pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn run(session: &mut Session, command: Command) -> CmdResult {
    match command {
        Command::Process(c) => process(session, c),
        Command::Memory(c) => memory(session, c),
        Command::Image(c) => image(session, c),
        Command::Scan(c) => scan(session, c),
        Command::Pointer(c) => pointer(session, c),
        Command::Table(c) => table(session, c),
        Command::Tui => crate::tui::run(session),
        // Handled by the REPL loop.
        Command::Quit => Ok(()),
    }
}

fn process(session: &mut Session, command: ProcessCommand) -> CmdResult {
    match command {
        ProcessCommand::List { filter } => {
            let mut processes: Vec<_> = procodile::process::processes()
                .map_err(|e| e.to_string())?
                .filter(|p| {
                    filter.as_ref().is_none_or(|f| {
                        p.name()
                            .to_string_lossy()
                            .to_lowercase()
                            .contains(&f.to_lowercase())
                    })
                })
                .collect();
            processes.sort_by_key(|p| p.pid());
            println!("{} matching processes were found", processes.len());
            println!("{:<8} {:<8} NAME", "PID", "PARENT");
            println!("{} {} {}", "=".repeat(8), "=".repeat(8), "=".repeat(32));
            for p in processes {
                let parent = p.parent_pid().map(|p| p.to_string()).unwrap_or_default();
                println!(
                    "{:<8} {:<8} {}",
                    p.pid(),
                    parent,
                    p.name().to_string_lossy()
                );
            }
        }
        ProcessCommand::Attach(args) => {
            let target = match (args.pid, args.name, args.target) {
                (Some(pid), _, _) => session.attach(pid)?,
                (_, Some(name), _) => session.attach_by_name(&name)?,
                (_, _, Some(t)) => match t.parse() {
                    Ok(pid) => session.attach(pid)?,
                    Err(_) => session.attach_by_name(&t)?,
                },
                _ => unreachable!("clap requires one"),
            };
            println!("Process {} ({}) attached", target.pid, target.name);
        }
        ProcessCommand::Detach => match session.detach() {
            Some(t) => println!("Process {} ({}) detached", t.pid, t.name),
            None => return Err("no process attached".into()),
        },
        ProcessCommand::Status => {
            let t = session.target()?;
            let state = if t.handle.is_alive() {
                "running"
            } else {
                "exited"
            };
            println!(
                "Process {} ({}) {state}, {}-bit",
                t.pid,
                t.name,
                t.pointer_width * 8
            );
            if let Some(scan) = &session.scan {
                println!("Scan: {} {} results", scan.len(), scan.value_type());
            }
            let frozen = session
                .table
                .entries
                .iter()
                .filter(|e| e.frozen.is_some())
                .count();
            println!(
                "Table: {} entries, {frozen} frozen",
                session.table.entries.len()
            );
        }
        ProcessCommand::Interrupt => {
            let t = session.target()?;
            t.handle.suspend().map_err(|e| e.to_string())?;
            println!("Process {} suspended", t.pid);
        }
        ProcessCommand::Continue => {
            let t = session.target()?;
            t.handle.resume().map_err(|e| e.to_string())?;
            println!("Process {} resuming", t.pid);
        }
    }
    Ok(())
}

fn memory(session: &mut Session, command: MemoryCommand) -> CmdResult {
    match command {
        MemoryCommand::Read {
            format,
            size,
            count,
            r#type,
            address,
        } => {
            let pointer_width = session.target()?.pointer_width;
            let (format, size) = match (r#type, format) {
                (Some(ty), None) => {
                    let (f, s) = Format::for_type(ty);
                    (f, size.unwrap_or(s))
                }
                (Some(_), Some(_)) => return Err("use either --type or --format".into()),
                (None, f) => {
                    let f = f.unwrap_or(Format::Bytes);
                    (f, size.unwrap_or(f.default_size(pointer_width)))
                }
            };
            if !matches!(size, 1 | 2 | 4 | 8)
                && !matches!(format, Format::Bytes | Format::Char | Format::CString)
            {
                return Err(format!("invalid item size {size} (expected 1, 2, 4 or 8)"));
            }
            let count = count.unwrap_or(match format {
                Format::Bytes | Format::Char => 32,
                Format::CString => 256,
                _ => 32 / size.max(1),
            });

            let address = session.eval(&address)?;
            let mut buf = vec![0; size * count];
            let read = session
                .handle()?
                .read_bytes(address, &mut buf)
                .map_err(|e| e.to_string())?;
            if read == 0 {
                return Err(format!("could not read memory at {address:?}"));
            }
            for line in format::memory(address, &buf[..read], format, size) {
                println!("{line}");
            }
            if read < buf.len() {
                println!("warning: only {read} of {} bytes could be read", buf.len());
            }
        }
        MemoryCommand::Write {
            size,
            r#type,
            address,
            values,
        } => {
            let bytes = encode_values(&values, r#type, size.unwrap_or(1))?;
            let address = session.eval(&address)?;
            session
                .handle()?
                .write_all(address, &bytes)
                .map_err(|e| e.to_string())?;
            println!("{} bytes written to {address:?}", bytes.len());
        }
        MemoryCommand::Region { all, address } => {
            let handle = session.handle()?;
            if all {
                for region in handle.regions().map_err(|e| e.to_string())? {
                    println!("{}", region_line(&region));
                }
            } else {
                let address = session.eval(address.as_deref().unwrap())?;
                let region = handle
                    .region_at(address)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("{address:?} is not in a mapped region"))?;
                println!("{}", region_line(&region));
            }
        }
        MemoryCommand::Find(args) => find(session, args)?,
        MemoryCommand::Protect {
            address,
            size,
            permissions,
        } => {
            let protection = parse_permissions(&permissions)?;
            let address = session.eval(&address)?;
            let old = session
                .handle()?
                .protect(address, size, protection)
                .map_err(|e| e.to_string())?;
            println!("{address:?}: {old} -> {protection}");
        }
        MemoryCommand::Allocate { size, permissions } => {
            let protection = parse_permissions(&permissions)?;
            let address = session
                .handle()?
                .allocate(size, protection)
                .map_err(|e| e.to_string())?;
            println!("allocated {size:#x} bytes at {address:?}");
        }
        MemoryCommand::Free { address } => {
            let address = session.eval(&address)?;
            session.handle()?.free(address).map_err(|e| e.to_string())?;
            println!("freed {address:?}");
        }
    }
    Ok(())
}

fn find(session: &Session, args: FindArgs) -> CmdResult {
    let pattern = if let Some(p) = &args.pattern {
        p.parse::<Pattern>().map_err(|e| e.to_string())?
    } else if let Some(s) = &args.string {
        Pattern::exact(s.as_bytes())
    } else {
        let ty = args.r#type.unwrap_or(session.default_type);
        let value = ty
            .parse(args.expression.as_deref().unwrap())
            .map_err(|e| e.to_string())?;
        Pattern::exact(&value.to_bytes())
    };
    let options = PatternOptions {
        range: module_range(session, args.module.as_deref())?,
        executable_only: args.executable,
        limit: args.count,
    };
    let handle = session.handle()?;
    let found = with_progress("searching", |progress| {
        find_pattern(handle, &pattern, &options, Some(progress))
    })?;
    if found.is_empty() {
        println!("data not found within the range.");
        return Ok(());
    }
    let modules = handle.modules().unwrap_or_default();
    for address in &found {
        println!(
            "data found at location: {address:?} {}",
            describe(&modules, *address)
        );
    }
    if found.len() == args.count {
        println!(
            "(stopped after {} matches; use --count for more)",
            args.count
        );
    }
    Ok(())
}

fn image(session: &mut Session, command: ImageCommand) -> CmdResult {
    let handle = session.handle()?;
    match command {
        ImageCommand::List { filter } => {
            let modules = handle.modules().map_err(|e| e.to_string())?;
            for (i, m) in modules.iter().enumerate() {
                let name = m.name.to_string_lossy();
                if filter.as_ref().is_some_and(|f| !name.contains(f.as_str())) {
                    continue;
                }
                println!("[{i:>3}] {} {:>#10x} {}", m.base, m.size, m.path.display());
            }
        }
        ImageCommand::Lookup { address } => {
            let address = session.eval(&address)?;
            let modules = handle.modules().map_err(|e| e.to_string())?;
            match modules.iter().find(|m| m.contains(address)) {
                Some(m) => println!(
                    "      Address: {}[{:#x}] ({}+{:#x})",
                    m.name.to_string_lossy(),
                    address - m.base,
                    m.name.to_string_lossy(),
                    address - m.base
                ),
                None => println!("      Address: {address:?} (not in a module)"),
            }
            if let Some(region) = handle.region_at(address).map_err(|e| e.to_string())? {
                println!("       Region: {}", region_line(&region));
            }
        }
    }
    Ok(())
}

fn scan(session: &mut Session, command: ScanCommand) -> CmdResult {
    match command {
        ScanCommand::First {
            settings,
            condition,
        } => {
            let ty = settings.r#type.unwrap_or(session.default_type);
            let compare = parse_condition(&condition, ty, true)?;
            let options = ScanOptions {
                alignment: settings.align.unwrap_or(0),
                writable_only: !settings.read_only,
                include_mapped: settings.mapped,
                range: module_range(session, settings.module.as_deref())?,
                float_tolerance: settings
                    .tolerance
                    .unwrap_or_else(|| default_tolerance(ty, &condition)),
                ..ScanOptions::new(ty)
            };
            session.scan = None;
            session.default_type = ty;
            let handle = session.handle()?;
            let start = Instant::now();
            let scan = with_progress("scanning", |progress| {
                Scan::first(handle, options, compare, Some(progress))
            })?;
            print_scan_summary(&scan, start);
            session.scan = Some(scan);
        }
        ScanCommand::Next { condition } => {
            let ty = session
                .scan
                .as_ref()
                .ok_or("no scan; use `scan first`")?
                .value_type();
            let compare = parse_condition(&condition, ty, false)?;
            let handle = session.target()?.handle.clone();
            let scan = session.scan.as_mut().unwrap();
            let start = Instant::now();
            with_progress("scanning", |progress| {
                scan.next(&handle, compare, Some(progress))
            })?;
            print_scan_summary(scan, start);
        }
        ScanCommand::List { count, start } => {
            let scan = session.scan.as_ref().ok_or("no scan; use `scan first`")?;
            if scan.is_snapshot() {
                println!(
                    "note: {} candidates from an unknown-value scan; narrow them with `scan next`",
                    scan.len()
                );
            }
            let modules = session.handle()?.modules().unwrap_or_default();
            for (i, m) in scan.results().enumerate().skip(start).take(count) {
                let current = session
                    .read_value(m.address, scan.value_type())
                    .map_or_else(|_| "??".to_owned(), |v| v.to_string());
                println!(
                    "#{i:<5} {} {:<24} previous: {:<12} current: {current}",
                    m.address,
                    describe(&modules, m.address),
                    m.value.to_string()
                );
            }
            let shown = scan.len().saturating_sub(start).min(count);
            if start + shown < scan.len() {
                println!("({} more; use --start/--count)", scan.len() - start - shown);
            }
        }
        ScanCommand::Reset => {
            session.scan = None;
            println!("scan discarded");
        }
    }
    Ok(())
}

fn pointer(session: &mut Session, command: PointerCommand) -> CmdResult {
    match command {
        PointerCommand::Scan {
            address,
            depth,
            max_offset,
            count,
            read_only,
        } => {
            let target = session.eval(&address)?;
            let options = PointerScanOptions {
                max_depth: depth,
                max_offset,
                max_results: count,
                writable_only: !read_only,
                ..Default::default()
            };
            let handle = session.handle()?;
            let start = Instant::now();
            let paths = with_progress("building pointer map", |progress| {
                scan_pointers(handle, target, &options, Some(progress))
            })?;
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "{} pointer paths to {target:?} ({elapsed:.2}s); see `pointer list`",
                paths.len()
            );
            if paths.len() == count {
                println!("(stopped after {count}; use --count for more)");
            }
            session.pointers = Some(PointerResults { target, paths });
        }
        PointerCommand::List { count, start } => {
            let results = session
                .pointers
                .as_ref()
                .ok_or("no pointer scan results; use `pointer scan`")?;
            let target = session.target()?;
            let modules = target.handle.modules().map_err(|e| e.to_string())?;
            println!("paths to {:?}:", results.target);
            for (i, path) in results.paths.iter().enumerate().skip(start).take(count) {
                let now = match path.resolve(&target.handle, &modules, target.pointer_width) {
                    Ok(a) if a == results.target => format!("{a:?}"),
                    Ok(a) => format!("{a:?} (moved)"),
                    Err(_) => "??".to_owned(),
                };
                println!("@{i:<5} {path}  -> {now}");
            }
            let shown = results.paths.len().saturating_sub(start).min(count);
            if start + shown < results.paths.len() {
                println!(
                    "({} more; use --start/--count)",
                    results.paths.len() - start - shown
                );
            }
        }
        PointerCommand::Filter { address } => {
            let target = session.eval(&address)?;
            let results = session
                .pointers
                .as_mut()
                .ok_or("no pointer scan results; use `pointer scan` or `pointer load`")?;
            let handle = &session.target.as_ref().ok_or("no process attached")?.handle;
            let before = results.paths.len();
            results.paths =
                filter_pointers(handle, &results.paths, target).map_err(|e| e.to_string())?;
            results.target = target;
            println!(
                "{} of {before} paths resolve to {target:?}",
                results.paths.len()
            );
        }
        PointerCommand::Save { path } => {
            let results = session
                .pointers
                .as_ref()
                .ok_or("no pointer scan results to save")?;
            let mut text = String::new();
            for p in &results.paths {
                text.push_str(&p.to_string());
                text.push('\n');
            }
            std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
            println!("saved {} paths to {}", results.paths.len(), path.display());
        }
        PointerCommand::Load { path } => {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let paths = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.parse::<PointerPath>().map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            println!("loaded {} paths from {}", paths.len(), path.display());
            println!("note: use `pointer filter <address>` to keep those that still match");
            session.pointers = Some(PointerResults {
                target: Address::NULL,
                paths,
            });
        }
        PointerCommand::Reset => {
            session.pointers = None;
            println!("pointer scan results discarded");
        }
    }
    Ok(())
}

fn print_scan_summary(scan: &Scan, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    match scan.len() {
        0 => println!("no results ({elapsed:.2}s)"),
        1 => println!("1 result ({elapsed:.2}s); see `scan list`"),
        n => println!("{n} results ({elapsed:.2}s); see `scan list`"),
    }
}

fn table(session: &mut Session, command: TableCommand) -> CmdResult {
    match command {
        TableCommand::Add {
            address,
            r#type,
            description,
        } => {
            let mut expr = crate::expr::parse(&address)?;
            let ty = r#type
                .or(session.scan.as_ref().map(Scan::value_type))
                .unwrap_or(session.default_type);
            // Scan results are only valid until the next scan: store the address itself,
            // or for a pointer path, the path as an expression.
            if let crate::expr::Expr::ScanResult(_) = expr {
                expr = crate::expr::Expr::Number(expr.eval(session)?.get() as u64);
            }
            let address = match expr {
                crate::expr::Expr::Number(n) => format!("{n:#x}"),
                crate::expr::Expr::PointerPath(i) => session.pointer(i)?.to_string(),
                _ => address,
            };
            session.eval(&address)?;
            session.table.entries.push(Entry {
                description: description.unwrap_or_default(),
                address,
                value_type: ty,
                frozen: None,
            });
            println!("added ${}", session.table.entries.len() - 1);
        }
        TableCommand::List => {
            if session.table.entries.is_empty() {
                println!("the address table is empty; add entries with `table add`");
            }
            for i in 0..session.table.entries.len() {
                println!("{}", table_line(session, i));
            }
        }
        TableCommand::Remove { index } => {
            session.remove_entry(index)?;
            println!("removed ${index}");
        }
        TableCommand::Write { index, value } => {
            let entry = session.table.get(index)?;
            let value = parse_value(entry.value_type, &value)?;
            let address = session.eval(&entry.address)?;
            if entry.frozen.is_some() {
                session.freeze(index, Some(value))?;
            }
            session.write_value(address, value)?;
            println!("{}", table_line(session, index));
        }
        TableCommand::Freeze { index, value } => {
            let ty = session.table.get(index)?.value_type;
            let value = value.map(|v| parse_value(ty, &v)).transpose()?;
            let value = session.freeze(index, value)?;
            println!("${index} frozen at {value}");
        }
        TableCommand::Unfreeze { index } => {
            if session.unfreeze(index)? {
                println!("${index} unfrozen");
            } else {
                println!("${index} was not frozen");
            }
        }
        TableCommand::Save { path } => {
            session.table.save(&path)?;
            println!(
                "saved {} entries to {}",
                session.table.entries.len(),
                path.display()
            );
        }
        TableCommand::Load { path } => {
            let table = crate::table::Table::load(&path)?;
            for i in 0..session.table.entries.len() {
                session.unfreeze(i)?;
            }
            session.table = table;
            println!(
                "loaded {} entries from {}",
                session.table.entries.len(),
                path.display()
            );
        }
    }
    Ok(())
}

pub fn table_line(session: &Session, index: usize) -> String {
    let entry = &session.table.entries[index];
    let frozen = if entry.frozen.is_some() { "*" } else { " " };
    let (address, value) = match session.read_entry(index) {
        Ok((a, Ok(v))) => (format!("{a:?}"), v.to_string()),
        Ok((a, Err(_))) => (format!("{a:?}"), "??".to_owned()),
        Err(e) => ("?".to_owned(), e),
    };
    format!(
        "${index:<3}{frozen} {:<16} {:<4} {:<18} = {:<12} [{}]",
        entry.description, entry.value_type, address, value, entry.address
    )
}

/// Runs `f` on a worker thread while showing a progress line, cancelling on Ctrl-C.
fn with_progress<T: Send>(
    verb: &str,
    f: impl FnOnce(&Progress) -> procodile::Result<T> + Send,
) -> Result<T, String> {
    let progress = Progress::new();
    INTERRUPTED.store(false, Ordering::Relaxed);
    let result = thread::scope(|s| {
        let worker = s.spawn(|| f(&progress));
        let start = Instant::now();
        let mut shown = false;
        while !worker.is_finished() {
            thread::sleep(Duration::from_millis(50));
            if INTERRUPTED.load(Ordering::Relaxed) {
                progress.cancel();
            }
            if start.elapsed() > Duration::from_millis(300) && progress.total() > 0 {
                eprint!(
                    "\r{verb}... {:>3.0}% of {}  (Ctrl-C to cancel) ",
                    progress.fraction() * 100.0,
                    format::bytes(progress.total())
                );
                shown = true;
            }
        }
        if shown {
            eprint!("\r\x1b[2K");
        }
        worker.join().expect("worker panicked")
    });
    result.map_err(|e| match e {
        procodile::Error::Cancelled => "interrupted".to_owned(),
        e => e.to_string(),
    })
}

/// Parses a scan condition: a bare value means `eq`.
pub(crate) fn parse_condition(
    words: &[String],
    ty: ValueType,
    first: bool,
) -> Result<Compare, String> {
    let (op, args) = match words[0].parse::<f64>().is_ok() || words[0].starts_with("0x") {
        true => ("eq", words),
        false => (words[0].as_str(), &words[1..]),
    };
    let value = |i: usize| -> Result<Value, String> {
        let s = args
            .get(i)
            .ok_or_else(|| format!("`{op}` needs {} value(s)", i + 1))?;
        parse_value(ty, s)
    };
    let expect = |n: usize| -> Result<(), String> {
        if args.len() > n {
            return Err(format!("too many values for `{op}`"));
        }
        Ok(())
    };
    let compare = match op {
        "eq" | "exact" | "=" | "==" => Compare::Exact(value(0)?),
        "ne" | "!=" => Compare::NotEqual(value(0)?),
        "gt" | ">" => Compare::GreaterThan(value(0)?),
        "lt" | "<" => Compare::LessThan(value(0)?),
        "between" | "range" => {
            let (a, b) = (value(0)?, value(1)?);
            expect(2)?;
            return Ok(Compare::Between(a, b));
        }
        "unknown" | "any" if first => Compare::Unknown,
        "changed" if !first => Compare::Changed,
        "unchanged" | "same" if !first => Compare::Unchanged,
        "increased" | "inc" | "+" if !first => Compare::Increased,
        "decreased" | "dec" | "-" if !first => Compare::Decreased,
        "inc-by" | "+=" if !first => Compare::IncreasedBy(value(0)?),
        "dec-by" | "-=" if !first => Compare::DecreasedBy(value(0)?),
        _ if first => {
            return Err(format!(
                "unknown condition '{op}' for a first scan (try a value, eq, ne, gt, lt, \
                 between or unknown)"
            ));
        }
        _ => {
            return Err(format!(
                "unknown condition '{op}' (try a value, eq, ne, gt, lt, between, changed, \
                 unchanged, increased, decreased, inc-by or dec-by)"
            ));
        }
    };
    let used = match compare {
        Compare::Unknown
        | Compare::Changed
        | Compare::Unchanged
        | Compare::Increased
        | Compare::Decreased => 0,
        _ => 1,
    };
    expect(used)?;
    Ok(compare)
}

/// Cheat Engine's "rounded" float matching: `1.5` matches anything that rounds to it.
pub(crate) fn default_tolerance(ty: ValueType, condition: &[String]) -> f64 {
    if !ty.is_float() {
        return 0.0;
    }
    let Some(value) = condition.iter().find(|w| w.parse::<f64>().is_ok()) else {
        return 0.0;
    };
    let decimals = value.split_once('.').map_or(0, |(_, frac)| frac.len());
    0.5 * 10f64.powi(-(decimals as i32))
}

pub(crate) fn parse_value(ty: ValueType, s: &str) -> Result<Value, String> {
    ty.parse(s).map_err(|e| e.to_string())
}

/// Without a type, values are hex integers of `size` bytes, as lldb prints memory:
/// `memory write addr de ad be ef`. With a type, they are parsed as that type.
fn encode_values(values: &[String], ty: Option<ValueType>, size: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for v in values {
        match ty {
            Some(ty) => bytes.extend(parse_value(ty, v)?.to_bytes()),
            None => {
                let digits = v.strip_prefix("0x").unwrap_or(v);
                let n = u64::from_str_radix(digits, 16)
                    .map_err(|_| format!("invalid hex value '{v}' (use --type for decimal)"))?;
                if !matches!(size, 1 | 2 | 4 | 8) || (size < 8 && n >> (size * 8) != 0) {
                    return Err(format!("'{v}' does not fit in {size} byte(s)"));
                }
                bytes.extend_from_slice(&n.to_ne_bytes()[..size]);
            }
        }
    }
    Ok(bytes)
}

fn parse_permissions(s: &str) -> Result<Protection, String> {
    let mut p = Protection::NONE;
    for c in s.chars() {
        p |= match c {
            'r' => Protection::READ,
            'w' => Protection::WRITE,
            'x' => Protection::EXECUTE,
            '-' => Protection::NONE,
            _ => {
                return Err(format!(
                    "invalid permissions '{s}' (expected e.g. rwx or r-x)"
                ));
            }
        };
    }
    Ok(p)
}

fn module_range(
    session: &Session,
    module: Option<&str>,
) -> Result<Option<std::ops::Range<Address>>, String> {
    let Some(name) = module else {
        return Ok(None);
    };
    let module = session
        .handle()?
        .module(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no module named '{name}'"))?;
    Ok(Some(module.base..module.end()))
}

fn region_line(r: &Region) -> String {
    let path = r.path.as_ref().map(|p| p.display().to_string());
    format!(
        "[{}-{}) {:<4} {:<7?} {}",
        r.base,
        r.end(),
        r.protection.to_string(),
        r.kind,
        path.unwrap_or_default()
    )
}

/// `module+0xoffset` when the address is inside a module.
pub fn describe(modules: &[Module], address: Address) -> String {
    modules
        .iter()
        .find(|m| m.contains(address))
        .map(|m| format!("{}+{:#x}", m.name.to_string_lossy(), address - m.base))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn conditions() {
        let ty = ValueType::I32;
        assert_eq!(
            parse_condition(&words("100"), ty, true).unwrap(),
            Compare::Exact(Value::I32(100))
        );
        assert_eq!(
            parse_condition(&words("-5"), ty, true).unwrap(),
            Compare::Exact(Value::I32(-5))
        );
        assert_eq!(
            parse_condition(&words("between 1 10"), ty, true).unwrap(),
            Compare::Between(Value::I32(1), Value::I32(10))
        );
        assert_eq!(
            parse_condition(&words("unknown"), ty, true).unwrap(),
            Compare::Unknown
        );
        assert!(parse_condition(&words("changed"), ty, true).is_err());
        assert_eq!(
            parse_condition(&words("dec"), ty, false).unwrap(),
            Compare::Decreased
        );
        assert_eq!(
            parse_condition(&words("dec-by 7"), ty, false).unwrap(),
            Compare::DecreasedBy(Value::I32(7))
        );
        assert!(parse_condition(&words("eq 1 2"), ty, false).is_err());
        assert!(parse_condition(&words("increased 1"), ty, false).is_err());
    }

    #[test]
    fn tolerance_follows_precision() {
        assert_eq!(default_tolerance(ValueType::F32, &words("100")), 0.5);
        assert!(
            (default_tolerance(ValueType::F32, &words("between 1.25 2")) - 0.005).abs() < 1e-12
        );
        assert_eq!(default_tolerance(ValueType::I32, &words("1.5")), 0.0);
    }

    #[test]
    fn write_values() {
        assert_eq!(
            encode_values(&words("de ad 0x01"), None, 1).unwrap(),
            [0xde, 0xad, 0x01]
        );
        assert_eq!(
            encode_values(&words("10"), None, 4).unwrap(),
            0x10u32.to_ne_bytes()
        );
        assert!(encode_values(&words("100"), None, 1).is_err());
        assert_eq!(
            encode_values(&words("-1.5"), Some(ValueType::F32), 1).unwrap(),
            (-1.5f32).to_ne_bytes()
        );
    }
}
