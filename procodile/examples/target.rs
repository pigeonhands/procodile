//! A toy process to practise scanning on: prints the address and value of a counter and
//! changes it each time Enter is pressed.
//!
//! `cargo run -p procodile --example target`

use std::hint::black_box;
use std::io::BufRead;

fn main() {
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
