extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

mod aes;
mod ctr;
mod oracle;

use std::io;

fn recover_plaintext(oracle: &oracle::Oracle, ciphertext: &[u8]) -> Vec<u8> {
    use std::iter::repeat;
    let zeros = repeat(0).take(ciphertext.len()).collect::<Vec<u8>>();
    let keystream = oracle.edit(ciphertext, 0, &zeros[..]);
    keystream.iter().zip(ciphertext.iter()).map(|(a,b)| a ^ b).collect()
}

fn read_base64_file(filename: &str) -> io::Result<Vec<u8>> {
    use std::io::prelude::*;
    use std::io::{Error, ErrorKind};
    use std::fs::File;
    use rustc_serialize::base64::FromBase64;
    let mut file = try!(File::open(filename));
    let mut contents_b64 = String::new();
    try!(file.read_to_string(&mut contents_b64));
    let contents_joined: String =
        contents_b64[..].chars().filter(|c| *c!='\n').collect();
    match contents_joined[..].from_base64() {
        Ok(vec) => Ok(vec),
        Err(e)  => Err(Error::new(ErrorKind::Other,
                       format!("Couldn't parse base 64: {}", e))
                      ),
    }
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let ecb_contents = read_base64_file(filename).unwrap();
    let contents = aes::aes_ecb_decrypt(&ecb_contents[..],
                                        &b"YELLOW SUBMARINE"[..]).unwrap();
    let oracle = oracle::Oracle::new();
    let ciphertext = oracle.encrypt(&contents);
    let v = recover_plaintext(&oracle, &ciphertext[..]);
    println!("{}", String::from_utf8(v).unwrap());
}
