use std::hint::black_box;
use std::ptr;

use super::*;

/// A heap buffer of `u32`s, scanned in isolation by restricting the scan's range to it.
struct Target {
    handle: ProcessHandle,
    buf: Box<[u32; 1024]>,
}

impl Target {
    fn new() -> Self {
        Self {
            handle: ProcessHandle::open_current().unwrap(),
            buf: Box::new([0; 1024]),
        }
    }

    fn address(&self, i: usize) -> Address {
        Address::new(&raw const self.buf[i] as usize)
    }

    fn set(&mut self, i: usize, v: u32) {
        unsafe { ptr::write_volatile(&raw mut self.buf[i], v) };
    }

    fn options(&self, ty: ValueType) -> ScanOptions {
        let start = self.address(0);
        ScanOptions {
            range: Some(start..start + size_of_val(&*self.buf)),
            ..ScanOptions::new(ty)
        }
    }

    fn addresses(scan: &Scan) -> Vec<Address> {
        scan.results().map(|m| m.address).collect()
    }
}

#[test]
fn exact_then_changed() {
    let mut t = Target::new();
    t.set(10, 1234);
    t.set(500, 1234);
    t.set(900, 99);

    let mut scan = Scan::first(
        &t.handle,
        t.options(ValueType::U32),
        Compare::Exact(Value::U32(1234)),
        None,
    )
    .unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(10), t.address(500)]);

    t.set(500, 1240);
    scan.next(&t.handle, Compare::Changed, None).unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(500)]);
    assert_eq!(scan.results().next().unwrap().value, Value::U32(1240));

    scan.next(&t.handle, Compare::DecreasedBy(Value::U32(6)), None)
        .unwrap();
    assert!(scan.is_empty());
}

#[test]
fn unknown_then_relative() {
    let mut t = Target::new();
    let mut scan =
        Scan::first(&t.handle, t.options(ValueType::U32), Compare::Unknown, None).unwrap();
    assert!(scan.is_snapshot());
    assert_eq!(scan.len(), 1024);

    t.set(7, 5);
    t.set(8, 5);
    scan.next(&t.handle, Compare::Increased, None).unwrap();
    assert!(!scan.is_snapshot());
    assert_eq!(Target::addresses(&scan), [t.address(7), t.address(8)]);

    t.set(8, 2);
    scan.next(&t.handle, Compare::Decreased, None).unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(8)]);

    scan.next(&t.handle, Compare::Unchanged, None).unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(8)]);
}

#[test]
fn unaligned_and_floats() {
    let mut t = Target::new();
    // 0x0000_2a00 at index 3 holds the u16 0x2a at an odd address.
    t.set(3, 0x2a00);
    let options = ScanOptions {
        alignment: 1,
        ..t.options(ValueType::U8)
    };
    let scan = Scan::first(&t.handle, options, Compare::Exact(Value::U8(0x2a)), None).unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(3) + 1]);

    t.set(20, 100.25f32.to_bits());
    let options = ScanOptions {
        float_tolerance: 0.5,
        ..t.options(ValueType::F32)
    };
    let scan = Scan::first(
        &t.handle,
        options,
        Compare::Between(Value::F32(99.0), Value::F32(101.0)),
        None,
    )
    .unwrap();
    assert_eq!(Target::addresses(&scan), [t.address(20)]);
}

#[test]
fn whole_process_scan_finds_heap_value() {
    let mut t = Target::new();
    t.set(42, 0x5eed_c0de);
    let scan = Scan::first(
        &t.handle,
        ScanOptions::new(ValueType::U32),
        Compare::Exact(Value::U32(black_box(0x5eed_c0de))),
        None,
    )
    .unwrap();
    assert!(Target::addresses(&scan).contains(&t.address(42)));
}

#[test]
fn rejects_invalid_scans() {
    let t = Target::new();
    let options = t.options(ValueType::U32);
    assert!(matches!(
        Scan::first(&t.handle, options.clone(), Compare::Changed, None),
        Err(Error::InvalidScan(_))
    ));
    assert!(matches!(
        Scan::first(&t.handle, options, Compare::Exact(Value::I64(1)), None),
        Err(Error::InvalidScan(_))
    ));
}

#[test]
fn cancelled_next_keeps_results() {
    let mut t = Target::new();
    let mut scan = Scan::first(
        &t.handle,
        t.options(ValueType::U32),
        Compare::Exact(Value::U32(0)),
        None,
    )
    .unwrap();
    let before = scan.len();
    t.set(0, 1);

    let progress = Progress::new();
    progress.cancel();
    assert!(matches!(
        scan.next(&t.handle, Compare::Unchanged, Some(&progress)),
        Err(Error::Cancelled)
    ));
    assert_eq!(scan.len(), before);
}
