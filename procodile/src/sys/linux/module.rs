use std::io;

use super::process::Handle;
use crate::Address;
use crate::module::Module;

const ELF_MAGIC: [u8; 4] = *b"\x7fELF";
const PE_MAGIC: [u8; 2] = *b"MZ";

impl Handle {
    /// Groups the private file mappings in `maps` by file, keeping those whose first
    /// mapping starts with an ELF header (so data files mapped with `mmap` are skipped).
    pub fn modules(&self) -> io::Result<Vec<Module>> {
        self.collect_images(false)
    }

    /// All file-backed images in the address space, including shared mappings
    /// (e.g. .NET assemblies memory-mapped by CoreCLR). Recognises both ELF
    /// and PE headers.
    pub fn mapped_images(&self) -> io::Result<Vec<Module>> {
        self.collect_images(true)
    }

    fn collect_images(&self, include_shared: bool) -> io::Result<Vec<Module>> {
        let mut modules: Vec<Module> = Vec::new();
        for entry in self.maps()? {
            if !include_shared && entry.shared {
                continue;
            }
            let Some(path) = entry.path() else {
                continue;
            };
            // Extend the most recent module with this path if the region is
            // adjacent (gap ≤ one 64K allocation granularity). Non-adjacent
            // mappings of the same file are ignored — the first mapping
            // (offset 0, with the image header) is the one we keep.
            if let Some(module) = modules.iter_mut().rev().find(|m| m.path == path) {
                if entry.start <= module.end().get() + 0x10000 {
                    let end = entry.end.max(module.end().get());
                    module.base = module.base.min(Address::new(entry.start));
                    module.size = end - module.base.get();
                }
                continue;
            }
            if entry.offset != 0 || !self.starts_with_image_header(entry.start) {
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

    fn starts_with_image_header(&self, address: usize) -> bool {
        let mut magic = [0u8; 4];
        if !matches!(self.read_at(Address::new(address), &mut magic), Ok(4)) {
            return false;
        }
        magic == ELF_MAGIC || magic[..2] == PE_MAGIC
    }
}
