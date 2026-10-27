//! Library injection: loading a shared library (`.dll` / `.so`) into another process.
//!
//! Two loading methods are available; use [`LoadMethod::Loader`] when the target process
//! has a cooperative OS loader, and [`LoadMethod::ManualMap`] when it does not (static
//! binaries, stripped symbol tables, ptrace-blocked environments, or when the image only
//! exists in memory and need never touch disk).

use std::path::Path;

use crate::sys::inject as imp;
use crate::{Error, Module, ProcessHandle, Result};

/// How a shared library is loaded into the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadMethod {
    /// Use the target's OS loader.
    ///
    /// Windows: `LoadLibraryW` via `CreateRemoteThread`.
    /// Linux: `dlopen` via ptrace (x86-64 only).
    ///
    /// The loaded library appears in the OS module list and is returned by
    /// [`ProcessHandle::modules`].
    #[default]
    Loader,
    /// Map the image directly into the target without involving the OS loader.
    ///
    /// Handles cases where [`LoadMethod::Loader`] cannot be used: static/musl targets
    /// with no usable `dlopen`, stripped symbols, ptrace-blocked environments, or when
    /// the image only exists in memory. A manually-mapped library is not registered with
    /// the OS loader, so it does not appear in the system's module list; procodile tracks
    /// it internally.
    ///
    /// x86-64 only in the current implementation.
    ManualMap,
}

impl ProcessHandle {
    /// Loads a shared library into the target process from a file on disk.
    ///
    /// `path` must be accessible in the target's filesystem context. Requires
    /// [`Access::ReadWrite`](crate::Access::ReadWrite) or
    /// [`Access::All`](crate::Access::All).
    ///
    /// Returns the newly loaded [`Module`]. For [`LoadMethod::Loader`] the module is
    /// discoverable via [`ProcessHandle::modules`]; for [`LoadMethod::ManualMap`] it is
    /// tracked by procodile internally.
    pub fn load_library(
        &self,
        path: impl AsRef<Path>,
        method: LoadMethod,
    ) -> Result<Module> {
        let path = path.as_ref();
        match method {
            LoadMethod::Loader => self.load_via_loader(path),
            LoadMethod::ManualMap => {
                let image = std::fs::read(path).map_err(|e| Error::Operation {
                    what: "read library file",
                    source: e,
                })?;
                self.map_image_bytes(&image, path.file_name())
            }
        }
    }

    /// Manually maps an image held entirely in memory into the target process.
    ///
    /// This is useful when the image never needs to exist as a file on disk.
    /// The mapped library is tracked by procodile internally and does not appear in the
    /// OS module list.
    ///
    /// x86-64 only in the current implementation.
    pub fn map_image(&self, image: &[u8]) -> Result<Module> {
        self.map_image_bytes(image, None)
    }

    fn load_via_loader(&self, path: &Path) -> Result<Module> {
        // Snapshot modules before so we can find the new entry afterwards.
        let before = self.modules().unwrap_or_default();

        let base = imp::load_library(self, path)
            .map_err(Error::operation("load library"))?;

        // Resolve the new module by finding it in the updated module list.
        // We prefer the entry whose base matches; fall back to name match.
        let after = self.modules()?;
        if let Some(m) = after.iter().find(|m| m.base == base) {
            return Ok(m.clone());
        }
        // Some platforms may return a slightly different base; try by file name.
        let name = path.file_name();
        if let Some(fname) = name {
            let was_present: std::collections::HashSet<_> =
                before.iter().map(|m| m.base).collect();
            if let Some(m) = after
                .into_iter()
                .find(|m| !was_present.contains(&m.base) && m.name == fname)
            {
                return Ok(m);
            }
        }
        Err(Error::Operation {
            what: "locate loaded module",
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "module not found in process after load",
            ),
        })
    }

    fn map_image_bytes(
        &self,
        image: &[u8],
        hint_name: Option<&std::ffi::OsStr>,
    ) -> Result<Module> {
        let (base, size) = imp::map_image(self, image, hint_name)
            .map_err(Error::operation("map image"))?;

        // The OS loader has no record of a manually-mapped image, so build the Module
        // from the information we have.
        let name = hint_name
            .unwrap_or_else(|| std::ffi::OsStr::new("<anonymous>"))
            .to_owned();
        Ok(Module {
            name,
            path: std::path::PathBuf::new(),
            base,
            size,
        })
    }
}
