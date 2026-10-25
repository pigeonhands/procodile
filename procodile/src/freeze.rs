//! Holding values in place by rewriting them on an interval.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{Address, ProcessHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FreezeId(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frozen {
    pub id: FreezeId,
    pub address: Address,
    pub bytes: Vec<u8>,
    /// Whether the most recent write succeeded.
    pub ok: bool,
}

/// A background thread that keeps writing a set of values to a process.
///
/// The thread stops when the `Freezer` is dropped.
pub struct Freezer {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

struct State {
    next_id: u64,
    entries: BTreeMap<FreezeId, Frozen>,
    interval: Duration,
    stop: bool,
}

impl Freezer {
    pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

    pub fn new(handle: Arc<ProcessHandle>) -> Self {
        Self::with_interval(handle, Self::DEFAULT_INTERVAL)
    }

    pub fn with_interval(handle: Arc<ProcessHandle>, interval: Duration) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                next_id: 0,
                entries: BTreeMap::new(),
                interval,
                stop: false,
            }),
            wake: Condvar::new(),
        });
        let thread = thread::Builder::new()
            .name("procodile-freezer".into())
            .spawn({
                let shared = shared.clone();
                move || run(&shared, &handle)
            })
            .expect("failed to spawn freezer thread");
        Self {
            shared,
            thread: Some(thread),
        }
    }

    /// Starts writing `bytes` to `address`. The first write happens immediately.
    pub fn freeze(&self, address: Address, bytes: Vec<u8>) -> FreezeId {
        let mut state = self.lock();
        let id = FreezeId(state.next_id);
        state.next_id += 1;
        state.entries.insert(
            id,
            Frozen {
                id,
                address,
                bytes,
                ok: true,
            },
        );
        drop(state);
        self.shared.wake.notify_all();
        id
    }

    /// Returns whether `id` was frozen.
    pub fn unfreeze(&self, id: FreezeId) -> bool {
        self.lock().entries.remove(&id).is_some()
    }

    /// Changes the value written for `id`. Returns whether `id` is frozen.
    pub fn set(&self, id: FreezeId, bytes: Vec<u8>) -> bool {
        let found = match self.lock().entries.get_mut(&id) {
            Some(entry) => {
                entry.bytes = bytes;
                true
            }
            None => false,
        };
        self.shared.wake.notify_all();
        found
    }

    pub fn clear(&self) {
        self.lock().entries.clear();
    }

    pub fn set_interval(&self, interval: Duration) {
        self.lock().interval = interval;
        self.shared.wake.notify_all();
    }

    pub fn entries(&self) -> Vec<Frozen> {
        self.lock().entries.values().cloned().collect()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Freezer {
    fn drop(&mut self) {
        self.lock().stop = true;
        self.shared.wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(shared: &Shared, handle: &ProcessHandle) {
    let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    while !state.stop {
        for entry in state.entries.values_mut() {
            entry.ok = handle.write_all(entry.address, &entry.bytes).is_ok();
        }
        let interval = state.interval;
        state = shared
            .wake
            .wait_timeout(state, interval)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;
    use std::time::Instant;

    use super::*;

    #[test]
    fn keeps_value_frozen() {
        let handle = Arc::new(ProcessHandle::open_current().unwrap());
        let mut value = Box::new(1u32);
        let address = Address::new(&raw const *value as usize);
        let read = |v: &u32| unsafe { ptr::read_volatile(v) };

        let freezer = Freezer::with_interval(handle, Duration::from_millis(5));
        let id = freezer.freeze(address, 50u32.to_ne_bytes().to_vec());

        let wait_for = |expected: u32, v: &u32| {
            let deadline = Instant::now() + Duration::from_secs(2);
            while read(v) != expected {
                assert!(Instant::now() < deadline, "value never became {expected}");
                thread::sleep(Duration::from_millis(1));
            }
        };
        wait_for(50, &value);

        unsafe { ptr::write_volatile(&raw mut *value, 7) };
        wait_for(50, &value);

        assert!(freezer.unfreeze(id));
        // Let any in-flight write land before checking the value stays put.
        thread::sleep(Duration::from_millis(20));
        unsafe { ptr::write_volatile(&raw mut *value, 7) };
        thread::sleep(Duration::from_millis(20));
        assert_eq!(read(&value), 7);
    }
}
