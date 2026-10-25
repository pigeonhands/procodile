//! A toy process to practise scanning on: prints the address and value of a counter and
//! changes it each time Enter is pressed.
//!
//! The counter lives behind a static pointer chain (`PLAYER -> Player.stats -> Stats.health`),
//! like game state usually does, so it can be found again with a pointer scan after a
//! restart moves it.
//!
//! `cargo run -p procodile --example target`

use std::hint::black_box;
use std::io::BufRead;
use std::sync::atomic::{AtomicPtr, Ordering};

#[allow(dead_code)]
struct Player {
    level: u32,
    name: String,
    stats: Box<Stats>,
}

#[allow(dead_code)]
struct Stats {
    armor: i32,
    mana: i32,
    health: i32,
}

static PLAYER: AtomicPtr<Player> = AtomicPtr::new(std::ptr::null_mut());

fn main() {
    // With Yama's ptrace_scope = 1, only ancestors may attach; let any process attach.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY);
    }

    // Some unrelated allocations first, so the heap layout is not trivial.
    let noise: Vec<Box<[u8; 64]>> = (0..100).map(|_| Box::new([0; 64])).collect();
    let player = Box::new(Player {
        level: 1,
        name: "hero".into(),
        stats: Box::new(Stats {
            armor: 5,
            mana: 50,
            health: 100,
        }),
    });
    PLAYER.store(Box::into_raw(player), Ordering::SeqCst);
    let stats = unsafe { &mut *(*PLAYER.load(Ordering::SeqCst)).stats };

    println!(
        "pid {}, health at {:p}",
        std::process::id(),
        &raw const stats.health
    );
    println!("Enter: take 7 damage | h: heal 10 | q: quit");

    for line in std::io::stdin().lock().lines() {
        match line.unwrap().trim() {
            "q" => break,
            "h" => stats.health += 10,
            _ => stats.health -= 7,
        }
        println!("health = {}", black_box(stats.health));
    }
    drop(noise);
}
