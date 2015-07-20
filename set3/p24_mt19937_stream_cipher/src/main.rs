extern crate rand;
extern crate time;

mod twister;
mod stream;
mod oracle;

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

fn main() {
    let mut oracle = oracle::Oracle::new();
    let user_controlled = "AAAAAAAAAAAAAA";
    let ciphertext = oracle.write(user_controlled);
    let seed = recover_seed(&ciphertext[..], user_controlled)
               .expect("Could not recover seed");
    println!("Recovered seed {}.", seed);
}
