//! Library injection: loading a shared library (`.dll` / `.so`) into another process.
//!
//! The OS-loader path ([`LoadMethod::Loader`]) is always available.
//!
//! Manual mapping ([`LoadMethod::ManualMap`] / [`ProcessHandle::map_image`]) requires the
//! `inject` feature, which brings in [`pewter`] for PE/ELF parsing.

use std::path::Path;

use crate::sys::inject as imp;
use crate::{Address, Error, Module, ProcessHandle, Result};

/// How a shared library is loaded into the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", repr(u8))]
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
    /// Requires the `inject` feature. Handles cases where [`LoadMethod::Loader`] cannot
    /// be used: static/musl targets with no usable `dlopen`, stripped symbols,
    /// ptrace-blocked environments, or when the image only exists in memory.
    ///
    /// x86-64 only in the current implementation.
    #[cfg(feature = "inject")]
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
            #[cfg(feature = "inject")]
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
    /// Requires the `inject` feature. The mapped library is tracked by procodile
    /// internally and does not appear in the OS module list.
    ///
    /// x86-64 only in the current implementation.
    #[cfg(feature = "inject")]
    pub fn map_image(&self, image: &[u8]) -> Result<Module> {
        self.map_image_bytes(image, None)
    }

    /// Manually maps an image from a file into the target process.
    ///
    /// Equivalent to reading `path` and calling [`map_image`](ProcessHandle::map_image),
    /// but derives the module name from the filename.
    ///
    /// Requires the `inject` feature.
    #[cfg(feature = "inject")]
    pub fn inject_file(&self, path: impl AsRef<Path>) -> Result<Module> {
        let path = path.as_ref();
        let image = std::fs::read(path).map_err(|e| Error::Operation {
            what: "read library file",
            source: e,
        })?;
        self.map_image_bytes(&image, path.file_name())
    }

    /// Allocates executable memory in the target and writes `data` into it, returning
    /// the base address of the new allocation.
    ///
    /// This is a low-level primitive — for loading a full shared library, use
    /// [`load_library`](ProcessHandle::load_library) or [`map_image`](ProcessHandle::map_image).
    pub fn inject_bytes(&self, data: &[u8]) -> Result<Address> {
        imp::inject_bytes(self, data).map_err(Error::operation("inject bytes"))
    }

    /// Starts execution at `entry` in the target process, passing `arg` as the first
    /// argument (`rdi` on x86-64 Linux, `rcx` on Windows). Blocks until the code returns.
    ///
    /// On Windows this creates a remote thread; on Linux it uses ptrace register
    /// manipulation (x86-64 only). The target must already contain executable code at
    /// `entry`.
    pub fn execute_remote(&self, entry: Address, arg: u64) -> Result<u64> {
        imp::execute_remote(self, entry, arg).map_err(Error::operation("execute remote"))
    }

    /// Spawns a new thread in the target process at `entry` with `arg` and returns
    /// immediately without waiting for it to finish.
    ///
    /// On Windows this creates a remote thread and closes the handle. On Linux it calls
    /// `pthread_create` + `pthread_detach` in the target via ptrace (x86-64 only).
    pub fn execute_remote_detached(&self, entry: Address, arg: u64) -> Result<()> {
        imp::execute_remote_detached(self, entry, arg)
            .map_err(Error::operation("execute remote detached"))
    }

    fn load_via_loader(&self, path: &Path) -> Result<Module> {
        let before = self.modules().unwrap_or_default();

        let base = imp::load_library(self, path)
            .map_err(Error::operation("load library"))?;

        let after = self.modules()?;
        if let Some(m) = after.iter().find(|m| m.base == base) {
            return Ok(m.clone());
        }
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

    #[cfg(feature = "inject")]
    fn map_image_bytes(
        &self,
        image: &[u8],
        hint_name: Option<&std::ffi::OsStr>,
    ) -> Result<Module> {
        let (base, size) = imp::map_image(self, image, hint_name)
            .map_err(Error::operation("map image"))?;

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
