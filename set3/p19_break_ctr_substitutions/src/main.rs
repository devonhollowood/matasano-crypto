extern crate crypto;
extern crate rustc_serialize;

mod aes;
mod ctr;
mod score;

use std::io;

fn crack(ciphertexts: &Vec<Vec<u8>>) -> Vec<u8> {
    let max_len = ciphertexts.iter().map(|v| v.len()).max().unwrap();
    let mut keystream = Vec::new();
    // I believe the text to only consist of characters in the range 0x20-0x7e,
    // so each character will be screened to make sure it in in this range
    let valid_char = |c| c >= 0x20 && c <= 0x7e;
    //take ciphertexts one index at a time
    for idx in 0..max_len {
        let mut best_byte = 0u8;
        let mut best_score = 0f32;
        // try each possible byte and select the best one
        'bytes: for test_byte in (0..256).map(|x| x as u8) {
            // get letters from this test byte
            let mut letters = String::new();
            for ciphertext in ciphertexts{
                if idx < ciphertext.len() {
                    let xor = test_byte ^ ciphertext[idx];
                    if !valid_char(xor) { // if any character is invalid, go on
                        continue 'bytes;  // to next test byte
                    }
                    else {
                        letters.push(xor as char);
                    }
                }
            }
            let score = score::score(&letters[..]);
            if score < best_score || best_score == 0f32 {
                best_score = score;
                best_byte = test_byte;
            }
        }
        keystream.push(best_byte);
    }
    keystream
}

fn base64_lines(filename: &str) -> io::Result<Vec<Vec<u8>>> {
    use std::io::prelude::*;
    use std::io::{Error, ErrorKind};
    use std::fs::File;
    use rustc_serialize::base64::FromBase64;
    //open file and read contents
    let mut file = try!(File::open(filename));
    let mut contents = String::new();
    try!(file.read_to_string(&mut contents));
    //base64 decode
    let mut lines = Vec::new();
    for line in contents.lines() {
        match line[..].from_base64() {
            Ok(vec) => lines.push(vec),
            Err(e)  => return Err(Error::new(ErrorKind::Other,
                                  format!("Couldn't parse base 64: {}", e))
                                 ),
        }
    }
    Ok(lines)
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let lines;
    match base64_lines(filename) {
        Ok(ls)  => lines = ls,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }
    let mut ciphertexts = Vec::new();
    let nonce = 0;
    let key = "YELLOW SUBMARINE".as_bytes();
    for line in lines {
        let mut encryptor = ctr::AesCtr::new(nonce, &key[..]);
        ciphertexts.push(encryptor.encrypt(&line[..]).unwrap());
    }
    let keystream = crack(&ciphertexts);
    for ciphertext in ciphertexts {
        for idx in 0..ciphertext.len() {
            print!("{}", (ciphertext[idx] ^ keystream[idx]) as char);
        }
        println!("");
    }
}
