use cbc;
use rand;

use std::io;

pub struct Oracle {
    key: [u8; 16],
    iv: [u8; 16],
    filename: String,
}

impl Oracle {
    pub fn new(filename: &str) -> Oracle {
        Oracle {
            key: random_block(),
            iv: random_block(),
            filename: filename.to_string(),
        }
    }

    #[cfg(test)]
    pub fn controlled(key : &[u8; 16], iv: &[u8; 16], filename: &str) -> Oracle {
        Oracle { key: key.clone(), iv: iv.clone(), filename: filename.to_string() }
    }

    pub fn get(&self) -> Vec<u8> {
        let text = match random_base64_line(&self.filename[..]) {
            Ok(v) => v,
            Err(e) => panic!("Error reading {}: {}", self.filename, e),
        };
        let encrypted = cbc::aes_cbc_encrypt(&text[..], &self.key, &self.iv);
        self.iv.iter().cloned().chain(encrypted.iter().cloned()).collect()
    }

    pub fn valid_padding(&self, ciphertext: &[u8]) -> bool {
        match cbc::aes_cbc_decrypt(ciphertext, &self.key, &self.iv) {
            Err(cbc::SymmetricCipherError::InvalidPadding) => false,
            _ => true,
        }
    }
}

fn random_block() -> [u8; 16] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut block = [0u8; 16];
    for el in block.iter_mut() {
        *el = rng.gen::<u8>();
    }
    block
}

fn random_base64_line(filename: &str) -> io::Result<Vec<u8>> {
    use std::io::prelude::*;
    use std::io::{Error, ErrorKind};
    use std::fs::File;
    use rustc_serialize::base64::FromBase64;
    use rand::{thread_rng, sample};
    //open file and read contents
    let mut file = try!(File::open(filename));
    let mut contents = String::new();
    try!(file.read_to_string(&mut contents));
    let lines = contents.lines();
    //randomly pick a line
    let mut rng = thread_rng();
    let sample = sample(&mut rng, lines, 1);
    if sample.len() != 1 { //had empty file
        return Err(Error::new(ErrorKind::Other, "Empty file"));
    }
    let chosen_line = sample.first().unwrap();
    //base64 decode
    match chosen_line[..].from_base64() {
        Ok(vec) => Ok(vec),
        Err(e)  => Err(Error::new(ErrorKind::Other,
                                  format!("Couldn't parse base 64: {}", e))
                      ),
    }
}
