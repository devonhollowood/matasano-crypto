#![feature(collections)]
#![feature(std_misc)]
#![feature(core)]

extern crate rand;
extern crate crypto;
mod ciphers;

fn detect_ecb(ciphertext: &[u8], blocksize: u16) -> bool {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry::{Occupied, Vacant};
    use std::num::Int;

    println!("ciphertext len: {}", ciphertext.len()); //debug
    //get blocks
    let blocks = ciphertext.chunks(blocksize as usize);
    let nblocks = blocks.len();

    //get number of repetitions
    let mut repetitions = HashMap::new();
    for block in blocks {
        for i in block.iter() { //debug
            print!("{:02x}", *i); //debug
        } //debug
        println!(""); //debug
        match repetitions.entry(block) {
            Vacant(entry)   => {entry.insert(0);},
            Occupied(mut entry) => *entry.get_mut() += 1,
        }
    }
    let mut nrepetitions = 0;
    for value in repetitions.values(){
        nrepetitions += *value;
    }

    //calculate probablility
    let expected =
        (nblocks.pow(2) as f32)/(2.pow(blocksize as u32) as f32);

    println!("nreps: {}", nrepetitions); //debug

    nrepetitions as f32 > expected
}

#[derive(PartialEq)]
enum Algorithm {
    ECB,
    CBC,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::ECB => write!(f, "ECB"),
            Algorithm::CBC => write!(f, "CBC"),
        }
    }
}

fn encryption_oracle(ciphertext: &[u8]) -> Algorithm {
    match detect_ecb(ciphertext, 16) {
        true  => Algorithm::ECB,
        false => Algorithm::CBC,
    }
}

fn generate_bytes<R: rand::Rng>(rng: &mut R, count: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(rng.gen());
    }
    result
}

fn choose_cipher<R: rand::Rng>(rng: &mut R) -> Algorithm {
    match rng.gen::<bool>() {
        true => Algorithm::ECB,
        false => Algorithm::CBC,
    }
}

fn create_cipher<R: rand::Rng>(rng: &mut R, plaintext: &[u8])
        -> (Vec<u8>, Algorithm) {
    use rand::sample;
    let before_size = sample(rng, 5..10, 1)[0];
    let before = &generate_bytes(rng, before_size)[..];
    let after_size = sample(rng, 5..10, 1)[0];
    let after = &generate_bytes(rng, after_size)[..];
    let algorithm = choose_cipher(rng);
    let key = &generate_bytes(rng, 16)[..];
    let mut input = Vec::new();
    println!("before: {:?}", before); //debug
    println!("plaintext len: {}", plaintext.len()); //debug
    println!("after: {:?}", after); //debug
    //input.push_all(&before[..]);
    input.push_all(plaintext);
    //input.push_all(&after[..]);
    let ciphertext = match algorithm {
        Algorithm::ECB => {
            ciphers::aes_ecb_encrypt(&input[..], &key[..]).unwrap()
        },
        Algorithm::CBC => {
            let iv = &generate_bytes(rng, 16)[..];
            ciphers::aes_cbc_encrypt(&input[..], key, iv).unwrap()
        },
    };
    (ciphertext, algorithm)
}

fn load_txt(filename: &str) -> Result<String, String> {
    use std::io::prelude::*;
    use std::fs::File;
    let mut f;
    match File::open(filename) {
        Ok(file) => f=file,
        Err(e)   => {
            return Err(format!("Couldn't open {}: {}", filename, e));
        }
    }
    let mut contents = String::new();
    match f.read_to_string(&mut contents) {
        Ok(_) => Ok(contents),
        Err(e) => Err(format!("Couldn't read {}: {}", filename, e)),
    }
}

fn main() {
    use rand::thread_rng;
    let plaintext = load_txt("red_and_black.txt").unwrap();
    let mut rng = thread_rng();
    let mut score = 0;
    let iterations = 10;
    for i in 0..iterations {
        let (ciphertext, answer) = create_cipher(&mut rng, &plaintext[..].as_bytes());
        let guessed = encryption_oracle(&ciphertext[..]);
        print!("{}: Guessed {}, Answer was {}. ", i, guessed, answer);
        if guessed==answer {
            println!("Correct!");
            score += 1;
        }
        else {
            println!("Incorrect =(");
        }
    }
    println!("Final score: {}/{}", score, iterations);
}
