use std::io;

use super::process::Handle;
use crate::Address;
use crate::module::Module;

const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

impl Handle {
    /// Groups the private file mappings in `maps` by file, keeping those whose first
    /// mapping starts with an ELF header (so data files mapped with `mmap` are skipped).
    pub fn modules(&self) -> io::Result<Vec<Module>> {
        let mut modules: Vec<Module> = Vec::new();
        for entry in self.maps()? {
            if entry.shared {
                continue;
            }
            let Some(path) = entry.path() else {
                continue;
            };
            if let Some(module) = modules.iter_mut().find(|m| m.path == path) {
                let end = entry.end.max(module.end().get());
                module.base = module.base.min(Address::new(entry.start));
                module.size = end - module.base.get();
                continue;
            }
            if entry.offset != 0 || !self.starts_with_elf_header(entry.start) {
                continue;
            }
            modules.push(Module {
                name: path.file_name().unwrap_or_default().to_owned(),
                base: Address::new(entry.start),
                size: entry.end - entry.start,
                path,
            });
        }
        Ok(modules)
    }

    fn starts_with_elf_header(&self, address: usize) -> bool {
        let mut magic = [0u8; 4];
        matches!(self.read_at(Address::new(address), &mut magic), Ok(4)) && magic == ELF_MAGIC
    }
}
