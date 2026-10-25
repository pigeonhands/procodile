//! State shared by the REPL and the TUI. Nothing here prints.

use std::sync::Arc;

use procodile::freeze::Freezer;
use procodile::scan::{Scan, Value, ValueType};
use procodile::{Access, Address, Process, ProcessHandle};

use crate::expr::{self, Env};
use crate::table::Table;

pub struct Target {
    pub pid: u32,
    pub name: String,
    pub handle: Arc<ProcessHandle>,
    pub freezer: Freezer,
    pub pointer_width: usize,
}

pub struct Session {
    pub target: Option<Target>,
    pub scan: Option<Scan>,
    pub table: Table,
    /// The value type for scans and table entries when none is given.
    pub default_type: ValueType,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            target: None,
            scan: None,
            table: Table::default(),
            default_type: ValueType::I32,
        }
    }
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn target(&self) -> Result<&Target, String> {
        self.target
            .as_ref()
            .ok_or_else(|| "no process attached; use `process attach -p <pid>`".to_owned())
    }

    pub fn handle(&self) -> Result<&ProcessHandle, String> {
        Ok(&self.target()?.handle)
    }

    pub fn attach(&mut self, pid: u32) -> Result<&Target, String> {
        let process = Process::by_pid(pid).map_err(|e| e.to_string())?;
        let handle = process.open(Access::ReadWrite).map_err(|e| {
            if e.is_permission_denied() {
                format!("{e}\n{}", permission_hint())
            } else {
                e.to_string()
            }
        })?;
        let handle = Arc::new(handle);
        self.detach();
        self.target = Some(Target {
            pid,
            name: process.name().to_string_lossy().into_owned(),
            pointer_width: handle.pointer_width().unwrap_or(size_of::<usize>()),
            freezer: Freezer::new(handle.clone()),
            handle,
        });
        Ok(self.target.as_ref().unwrap())
    }

    pub fn attach_by_name(&mut self, name: &str) -> Result<&Target, String> {
        let mut matches: Vec<u32> = Process::by_name(name)
            .map_err(|e| e.to_string())?
            .map(|p| p.pid())
            .collect();
        match matches.len() {
            0 => Err(format!("no process named '{name}'")),
            1 => self.attach(matches[0]),
            _ => {
                matches.sort_unstable();
                let pids: Vec<String> = matches.iter().map(u32::to_string).collect();
                Err(format!(
                    "more than one process named '{name}' (pids {}); use `process attach -p <pid>`",
                    pids.join(", ")
                ))
            }
        }
    }

    /// Drops the target and the scan. The address table is kept, unfrozen.
    pub fn detach(&mut self) -> Option<Target> {
        self.scan = None;
        for entry in &mut self.table.entries {
            entry.frozen = None;
        }
        self.target.take()
    }

    pub fn eval(&self, input: &str) -> Result<Address, String> {
        expr::parse(input)?.eval(self)
    }

    /// The address and current value of a table entry.
    pub fn read_entry(&self, index: usize) -> Result<(Address, Result<Value, String>), String> {
        let entry = self.table.get(index)?;
        let address = self.eval(&entry.address)?;
        Ok((address, self.read_value(address, entry.value_type)))
    }

    pub fn read_value(&self, address: Address, ty: ValueType) -> Result<Value, String> {
        let bytes = self
            .handle()?
            .read_vec(address, ty.size())
            .map_err(|e| e.to_string())?;
        Ok(ty.decode(&bytes))
    }

    pub fn write_value(&self, address: Address, value: Value) -> Result<(), String> {
        self.handle()?
            .write_all(address, &value.to_bytes())
            .map_err(|e| e.to_string())
    }

    /// Freezes entry `index` at `value`, or at its current value.
    pub fn freeze(&mut self, index: usize, value: Option<Value>) -> Result<Value, String> {
        let (address, current) = self.read_entry(index)?;
        let value = match value {
            Some(v) => v,
            None => current?,
        };
        self.unfreeze(index)?;
        let id = self.target()?.freezer.freeze(address, value.to_bytes());
        self.table.get_mut(index)?.frozen = Some(id);
        Ok(value)
    }

    pub fn unfreeze(&mut self, index: usize) -> Result<bool, String> {
        let entry = self.table.get_mut(index)?;
        let Some(id) = entry.frozen.take() else {
            return Ok(false);
        };
        if let Some(target) = &self.target {
            target.freezer.unfreeze(id);
        }
        Ok(true)
    }

    pub fn remove_entry(&mut self, index: usize) -> Result<(), String> {
        self.unfreeze(index)?;
        self.table.entries.remove(index);
        Ok(())
    }
}

impl Env for Session {
    fn module_base(&self, name: &str) -> Result<Address, String> {
        self.handle()?
            .module(name)
            .map_err(|e| e.to_string())?
            .map(|m| m.base)
            .ok_or_else(|| format!("no module named '{name}'"))
    }

    fn read_pointer(&self, address: Address) -> Result<Address, String> {
        let target = self.target()?;
        target
            .handle
            .read_pointer(address, target.pointer_width)
            .map_err(|e| e.to_string())
    }

    fn table_entry(&self, index: usize) -> Result<Address, String> {
        let entry = self.table.get(index)?;
        // Guard against `$0` referring to itself.
        let parsed = expr::parse(&entry.address)?;
        if references_table(&parsed) {
            return Err(format!(
                "table entry ${index} refers to another table entry"
            ));
        }
        parsed.eval(self)
    }

    fn scan_result(&self, index: usize) -> Result<Address, String> {
        let scan = self
            .scan
            .as_ref()
            .ok_or("no scan results; use `scan first`")?;
        scan.results()
            .nth(index)
            .map(|m| m.address)
            .ok_or_else(|| format!("no scan result #{index} ({} results)", scan.len()))
    }
}

fn references_table(e: &expr::Expr) -> bool {
    use expr::Expr::*;
    match e {
        Table(_) => true,
        Deref(a) => references_table(a),
        Add(a, b) | Sub(a, b) => references_table(a) || references_table(b),
        Number(_) | Module(_) | ScanResult(_) => false,
    }
}

pub fn permission_hint() -> &'static str {
    if cfg!(target_os = "linux") {
        "note: reading another process needs ptrace permission: run as root, grant \
         CAP_SYS_PTRACE, or set /proc/sys/kernel/yama/ptrace_scope to 0"
    } else {
        "note: try running as Administrator"
    }
}
