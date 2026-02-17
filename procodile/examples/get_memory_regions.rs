use procodile::Process;

fn mapped_memory_regions() {
    let current_process = Process::open_current_process().unwrap();

    println!("# mapped memory regions #");

    let mut total_regions = 0;
    let mut total_memory = 0;
    for region in current_process
        .active_memory_regions()
        .unwrap()
        .inspect(|r| {
            total_regions += 1;
            total_memory += r.memory_size
        })
    {
        let prot = if region.is_execute() {
            "x"
        } else if region.is_read_only() {
            "r"
        } else if region.is_read_write() {
            "rw"
        } else if region.is_read_execute() {
            "xr"
        } else {
            "?"
        };
        println!(
            "base address: 0x{:x} | size: 0x{:x} | protection: {} ({})",
            region.base_address,
            region.memory_size,
            prot,
            region.flags & 0b_11111
        );
    }
    println!(
        "# end of mapped memory regions (n: {} | size: 0x{:x}) #",
        total_regions, total_memory
    )
}

fn all_memory_regions() {
    let current_process = Process::open_current_process().unwrap();

    println!("# all memory regions #");
    let mut total_regions = 0;
    let mut total_memory = 0;
    for region in current_process
        .memory_regions(0 as *const _, 0x00007fffffffffff as *const _)
        .unwrap()
        .inspect(|r| {
            total_regions += 1;
            total_memory += r.region_size()
        })
    {
        let prot = if region.is_execute() {
            "x"
        } else if region.is_read_only() {
            "r"
        } else if region.is_read_write() {
            "rw"
        } else if region.is_read_execute() {
            "xr"
        } else {
            "?"
        };
        println!(
            "base address: {:?} | size: 0x{:x} | protection: {} ({})",
            region.base_address(),
            region.region_size(),
            prot,
            region.raw_protection_flags()
        );
    }

    println!(
        "# end of all memory regions  (n: {} | size: 0x{:x}) #",
        total_regions, total_memory
    )
}

fn main() {
    mapped_memory_regions();
    all_memory_regions();
}
