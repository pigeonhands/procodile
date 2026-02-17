use procodile::Process;

static TEST_DATA: usize = 0xDEADBEEF_AABBCCDD;

fn main() {
    let current_process = Process::open_current_process().unwrap();

    let val: usize = current_process
        .read_memory(&TEST_DATA as *const usize as *const _)
        .unwrap();

    assert_eq!(TEST_DATA, val);
    println!("Read value: 0x{:x}", TEST_DATA);
}
