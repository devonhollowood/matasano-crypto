#![allow(dead_code)]
extern crate rustc_serialize as serialize;
extern crate crypto;
extern crate rand;

mod aes;
mod ecb;
mod oracle;
use oracle::AesEcbOracle;

fn find_blocksize(oracle: &AesEcbOracle) -> usize {
    let mut blocksize = 1usize;
    loop {
        let current = oracle.encrypt(&vec![0x41; blocksize][..]);
        let next = oracle.encrypt(&vec![0x41; blocksize+1][..]);
        if next[0..blocksize]==current[0..blocksize] {
            if oracle.encrypt(&vec![0x42; blocksize][..])[0..blocksize] ==
               oracle.encrypt(&vec![0x42; blocksize+1][..])[0..blocksize] {
               return blocksize;
            }
        }
        blocksize += 1;
    }
}

#[test]
fn find_blocksize_test() {
    let oracle = AesEcbOracle::new("hello world".as_bytes());
    assert_eq!(find_blocksize(&oracle), 16);
}

fn crack_block(oracle: &AesEcbOracle, blocksize: usize,
               so_far : &[u8]) -> Vec<u8> {
    let target_idx = so_far.len()/blocksize; //index of targeted block
    let mut solved = Vec::new();
    while solved.len() < blocksize {
        let pad = vec![0; blocksize-solved.len()-1];
        let pad_encrypted = oracle.encrypt(&pad[..]);
        let target_block = pad_encrypted.chunks(blocksize).nth(target_idx)
                                        .unwrap();
        let mut test = pad.iter().cloned().chain(
            so_far.iter().cloned()
        ).chain(
            solved.iter().cloned()
        ).collect::<Vec<u8>>();
        let mut found=false;
        for byte in (0..256).map(|x| x as u8) {
            test.push(byte); //add test byte
            let encrypted = oracle.encrypt(&test[..]);
            let test_block = encrypted.chunks(blocksize)
                                      .nth(target_idx).unwrap();
            test.pop(); //clean up
            if test_block == target_block {
                found = true;
                solved.push(byte);
                break;
            }
        }
        if !found {
            // If this approach suddenly fails, you've hit the pad at the end of
            // the message, which shifts each time you change the pad length.
            // This gives a "moving target" for the last few bytes. It'll fail
            // after appending a 0x01, and the pad changes to 0x02 0x02. Thus
            // you can "fix" the issue by just popping the 0x01 byte and
            // re-padding.
            solved.pop();
            return aes::pkcs_pad(&solved[..], blocksize as u8);
        }
    }
    solved
}

fn crack_ecb_oracle(oracle: &AesEcbOracle)
        -> Result<Vec<u8>, String> {
    let blocksize = find_blocksize(oracle);
    let ciphertext = oracle.encrypt(&[]);
    let ecb_test = vec![0x41; 2*blocksize].into_iter().chain(
        ciphertext.iter().cloned()
    ).collect::<Vec<u8>>();
    if !ecb::detect_ecb(&ecb_test[..], blocksize) {
        return Err("Wasn't ecb".to_string());
    }
    let mut so_far = Vec::<u8>::new();
    while so_far.len() < ciphertext.len() {
        let next = crack_block(oracle, blocksize, &so_far[..]);
        so_far.extend(next);
    }
    Ok(so_far)
}

fn read_base64_file(filename: &str) -> Result<Vec<u8>,String> {
    use std::io::prelude::*;
    use std::fs::File;
    use self::serialize::base64::FromBase64;
    let mut f;
    match File::open(filename) {
        Ok(file) => f=file,
        Err(e)   => {
            return Err(format!("Couldn't open {}: {}", filename, e));
        }
    }
    let mut contents_b64 = String::new();
    match f.read_to_string(&mut contents_b64) {
        Ok(_) => {},
        Err(e) => {
            return Err(format!("Couldn't read {}: {}", filename, e));
        }
    }
    let contents_joined: String =
        contents_b64[..].chars().filter(|c| *c!='\n').collect();
    match contents_joined[..].from_base64() {
        Ok(vec) => Ok(vec),
        Err(e)  => Err(format!("Couldn't parse base 64: {}", e)),
    }
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let contents;
    match read_base64_file(filename) {
        Ok(c)  => contents = c,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }
    let oracle = AesEcbOracle::new(&contents[..]);
    let output;
    match crack_ecb_oracle(&oracle){
        Ok(v)  => match String::from_utf8(v) {
                      Ok(result) => output = format!("{}", result),
                      Err(e) => output = format!("{}", e),
                  },
        Err(e) => output = format!("Error: {}", e),
    }
    println!("{}", output)
}
