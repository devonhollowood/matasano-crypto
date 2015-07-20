extern crate rand;
extern crate time;

mod twister;
mod stream;
mod oracle;

/// Recovers a seed from a mt19937 stream cipher, given a ciphertext
/// `ciphertext` whose plaintext ends with `trailing_plaintext`
fn recover_seed(ciphertext: &[u8], trailing_plaintext: &str) -> Option<u16> {
    let plaintext_start = ciphertext.len() - trailing_plaintext.len();
    for seed in (0..65536).map(|x| x as u16) {
        let mut decryptor = stream::Decryptor::new(seed);
        if &decryptor.decrypt(ciphertext)[plaintext_start..]
            == trailing_plaintext.as_bytes() {
            return Some(seed);
        }
    }
    None
}

/// Demonstrates seed recovery
fn perform_seed_recovery() {
    let mut oracle = oracle::Oracle::new();
    let user_controlled = "AAAAAAAAAAAAAA";
    let ciphertext = oracle.write(user_controlled);
    let seed = recover_seed(&ciphertext[..], user_controlled)
               .expect("Could not recover seed");
    println!("Recovered seed {}.", seed);
}

/// Finds seed which produces `first` on its first output, given that it was
/// seeded with the current time sometime in the past `n_secs` seconds
fn check_seeds(first: u32, n_secs: u32) -> Option<u32> {
    let now = time::get_time().sec as u32;
    for s in ((now+1-n_secs)..now+1).rev() {
        let mut t = twister::Twister::new(s);
        if t.next().unwrap() == first {
            return Some(s);
        }
    }
    None
}

/// Demonstrates PasswordToken cracking, checking to see if the reset token
/// is from a mt19937 which was seeded with the current time in the last
/// `n_secs` seconds
fn perform_token_crack(n_secs: u32) {
    let now = time::get_time().sec as u32;
    println!("Cracking PasswordToken::from_time()");
    let token_a = oracle::PasswordToken::from_time().token();
    match check_seeds(token_a, n_secs) {
        Some(seed) => println!("...recovered seed {} from {} seconds ago", seed,
                               now-seed),
        None       => println!("...this was not seeded with a current time"),
    }
    println!("Cracking PasswordToken::random()");
    let token_b = oracle::PasswordToken::random().token();
    match check_seeds(token_b, n_secs) {
        Some(seed) => println!("...recovered seed {} from {} seconds ago", seed,
                               now-seed),
        None       => println!("...this was not seeded with a current time"),
    }
}

fn main() {
    perform_seed_recovery();
    perform_token_crack(100);
}
