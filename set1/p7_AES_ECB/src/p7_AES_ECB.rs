#![feature(collections)]
#![feature(io)]
extern crate "rustc-serialize" as serialize;
extern crate crypto;

use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

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

fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength, InvalidPadding};
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e {
                InvalidLength => return Err(str::to_string("Invalid Length")),
                InvalidPadding => return Err(str::to_string("Invalid Padding")),
            },
        }
        final_result.push_all(
            write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=3 {
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
    let ciphertext = &contents[..];
    let key = args[2][..].as_bytes();

    match aes_ecb_decrypt(ciphertext, key) {
        Ok(v)  => match String::from_utf8(v) {
            Ok(s)  => println!("{}", s),
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("Error: {:?}", e),
    }
}
