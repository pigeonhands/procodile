use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::{Address, Error, ProcessHandle, Result};

/// An executable image (exe, dll, so) loaded into a process.
///
/// Reflected as an opaque type because its `name` and `path` fields are `OsString` /
/// `PathBuf`, which do not implement `Facet`. The `base` and `size` can be read
/// directly after casting or through the platform-specific accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", facet(opaque))]
pub struct Module {
    /// File name, e.g. `game.exe` or `libc.so.6`.
    pub name: OsString,
    pub path: PathBuf,
    pub base: Address,
    /// Span from `base` to the end of the image's last mapping.
    pub size: usize,
}

impl Module {
    pub fn end(&self) -> Address {
        self.base + self.size
    }

    pub fn contains(&self, address: Address) -> bool {
        (self.base..self.end()).contains(&address)
    }
}

impl ProcessHandle {
    /// Loaded modules, in address order. The main executable is usually first on Windows,
    /// and at the lowest image address on Linux.
    pub fn modules(&self) -> Result<Vec<Module>> {
        let mut modules = self.0.modules().map_err(Error::query("modules"))?;
        modules.sort_by_key(|m| m.base);
        Ok(modules)
    }

    /// Finds a module by file name. An exact match wins; otherwise case is ignored.
    pub fn module(&self, name: impl AsRef<OsStr>) -> Result<Option<Module>> {
        let name = name.as_ref();
        let modules = self.modules()?;
        if let Some(i) = modules.iter().position(|m| m.name == name) {
            return Ok(modules.into_iter().nth(i));
        }
        let name = name.to_string_lossy();
        Ok(modules
            .into_iter()
            .find(|m| m.name.to_string_lossy().eq_ignore_ascii_case(&name)))
    }

    pub fn module_at(&self, address: Address) -> Result<Option<Module>> {
        Ok(self.modules()?.into_iter().find(|m| m.contains(address)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_executable_is_a_module() {
        let handle = ProcessHandle::open_current().unwrap();
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap();

        let module = handle.module(name).unwrap().expect("own module listed");
        assert_eq!(module.path, exe);

        let code = Address::new(own_executable_is_a_module as fn() as usize);
        assert_eq!(handle.module_at(code).unwrap().as_ref(), Some(&module));
    }
}
