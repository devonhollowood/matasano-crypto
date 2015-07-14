extern crate rand;
extern crate time;

mod twister;

/// Gets current time in seconds since the epoch
fn current_time() -> u32 {
    time::get_time().sec as u32
}

/// Creates an mt19937, seeded by the current time and cleverly hidden by
/// waiting 40-1000 seconds on either side.
fn create_twister() -> twister::Twister {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let before: u32 = rng.gen_range(40, 1000);
    let after: u32 = rng.gen_range(40, 1000);
    std::thread::sleep_ms(before*1000);
    let seed = current_time();
    std::thread::sleep_ms(after*1000);
    println!("Using seed {}. Shhhh!", seed);
    twister::Twister::new(seed)
}

/// Finds seed which produces `first` on its first output, given that it was
/// seeded with the current time sometime in the past 2000 seconds
fn crack_seed(first: u32) -> Option<u32> {
    let now = current_time();
    for s in (now-2000)..now {
        let mut t = twister::Twister::new(s);
        if t.next().unwrap() == first {
            return Some(s);
        }
    }
    None
}

fn main() {
    let mut t = create_twister();
    let first = t.next().unwrap();
    match crack_seed(first) {
        Some(seed) => println!("Cracked seed: {}", seed),
        None       => println!("Couldn't crack it!"),
    }
}
