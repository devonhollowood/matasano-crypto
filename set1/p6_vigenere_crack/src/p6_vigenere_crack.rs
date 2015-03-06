extern crate "rustc-serialize" as serialize;
mod hex;
mod hamming;
mod score;
mod cracks;

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
    match read_base64_file(&args[1][..]) {
        Ok(c)  => contents = c,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }
    let key;
    let plainhex;
    match cracks::vigenere_crack(&contents[..]) {
        Some(vec)  => {
            key = vec;
            plainhex = hex::repeated_key_xor(&contents[..], &key[..]);
        }
        None => {
            println!("Could not decode: {}", filename);
            return;
        }
    }
    let plaintext = String::from_utf8(plainhex).unwrap();
    println!("Decoded message was:\n\n{}\n\nKey was: {:?}", plaintext, key);
    match String::from_utf8(key){
        Ok(s) => println!("({})", s),
        Err(_) => {},
    }
}
