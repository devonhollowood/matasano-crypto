#![allow(dead_code)]
extern crate crypto;
extern crate rand;
extern crate regex;

mod aes;
mod profile;

use profile::{Profile, ProfileError};

struct ProfileOracle {
    key: [u8; 16],
}

impl ProfileOracle {
    fn new() -> ProfileOracle {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        for el in key.iter_mut() {
            *el = rng.gen::<u8>();
        }
        ProfileOracle { key: key }
    }

    fn with_key(key: &[u8; 16]) -> ProfileOracle {
        ProfileOracle { key: key.clone() }
    }

    fn is_admin(&self, ciphertext: &[u8]) -> bool {
        match Profile::decrypt(ciphertext, &self.key) {
            Ok(p) => p.is_admin(),
            Err(_) => false,
        }
    }

    fn profile_for(&self, email: &str) -> Vec<u8> {
        Profile::profile_for(email).encrypt(&self.key)
    }

    fn get_profile(&self, ciphertext: &[u8]) -> Result<Profile, ProfileError> {
        Profile::decrypt(ciphertext, &self.key)
    }
}

fn gain_admin(oracle: &ProfileOracle) -> Profile {
    use std::iter::repeat;
    // step one: get a ciphertext block corresponding to "admin[pkcs7_pad...]"

    // this is the required email length to align the block
    let admin_block_email_len = 16-"email=".len();
    let admin_block_pad_len = 16 - "admin".len();
    let admin_block_email = repeat('A').take(admin_block_email_len).chain(
        "admin".chars()
    ).chain(
        repeat(admin_block_pad_len as u8 as char).take(admin_block_pad_len)
    ).collect::<String>();
    let admin_block_profile = oracle.profile_for(&admin_block_email[..]);
    let admin_block = admin_block_profile.chunks(16).nth(1).unwrap();

    // step two: get a ciphertext block corresponding to an email of proper
    // length to align the above admin block
    let email_len = 16 - ("email=&uid=10&role=".len() % 16);
    let email = repeat('A').take(email_len).collect::<String>();
    let email_block_profile = oracle.profile_for(&email[..]);
    let email_block = email_block_profile.iter().take(32);

    let ciphertext = email_block.into_iter().chain(admin_block.into_iter())
                                .map(|c| *c).collect::<Vec<u8>>();
    println!("Submitting ciphertext: {}", format_hex(&ciphertext[..]));
    oracle.get_profile(&ciphertext[..]).unwrap()
}

fn format_hex(hex: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for el in hex.iter() {
        write!(&mut s, "{:02x}", el).unwrap();
    }
    s
}

fn main() {
    let oracle = ProfileOracle::new();
    let profile = gain_admin(&oracle);
    println!("Profile:");
    println!("\temail: {}", profile.email);
    println!("\tuid: {}", profile.uid);
    println!("\trole: {}", profile.role);
}
