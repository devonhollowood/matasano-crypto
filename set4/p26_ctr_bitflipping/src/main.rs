extern crate crypto;
extern crate rand;

mod aes;
mod ctr;
mod oracle;
use oracle::Oracle;

fn gain_admin(oracle: &Oracle) -> Vec<u8>{
    use std::iter::repeat;
    let injection = "user=admin";
    let aaa = repeat('A').take(injection.len()).collect::<String>();
    let canvas = oracle.encrypt(&aaa[..]);
    let prefix = "comment1=cooking%20MCs;userdata=";
    let target_idx = prefix.len(); //start of As
    let mut paint = canvas.clone();
    for idx in 0..injection.len() {
        paint[target_idx + idx] ^= injection.as_bytes()[idx] ^ ('A' as u8);
    }
    paint
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
    let oracle = Oracle::new();
    let admin_ciphertext = gain_admin(&oracle);
    println!("Submitting ciphertext: {}", format_hex(&admin_ciphertext[..]));
    println!("Admin: {}", oracle.is_admin(&admin_ciphertext[..]));
}
