#![feature(collections)]
#![feature(io)]
extern crate crypto;
extern crate "rustc-serialize" as serialize;

mod CBC;

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
    use self::serialize::hex::FromHex;
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=4 {
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
    let iv;
    match args[3][..].from_hex(){
        Ok(s)  => iv = s,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }

    match CBC::aes_cbc_decrypt(ciphertext, key, &iv) {
        Ok(v)  => match String::from_utf8(v) {
            Ok(s)  => println!("{}", s),
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("Error: {:?}", e),
    }
}
