//! A toy process to practise scanning on: prints the address and value of a counter and
//! changes it each time Enter is pressed.
//!
//! `cargo run -p procodile --example target`

use std::hint::black_box;
use std::io::BufRead;

fn main() {
    // With Yama's ptrace_scope = 1, only ancestors may attach; let any process attach.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY);
    }

    let mut health: Box<i32> = Box::new(100);
    println!(
        "pid {}, health at {:p}",
        std::process::id(),
        &raw const *health
    );
    println!("Enter: take 7 damage | h: heal 10 | q: quit");

    for line in std::io::stdin().lock().lines() {
        match line.unwrap().trim() {
            "q" => break,
            "h" => *health += 10,
            _ => *health -= 7,
        }
        println!("health = {}", black_box(&*health));
    }
}
