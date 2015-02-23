extern crate "rustc-serialize" as serialize;

mod hex{
    pub fn xor(a: &String, b: &String) -> Result<String, String> {
        use serialize::hex::{FromHex, ToHex};
        use std::vec::Vec;
        if a.len()!=b.len() {return Err("Lengths not equal".to_string());}
        let a_bytes : Vec<u8>;
        let b_bytes : Vec<u8>;
        match a.from_hex() {
            Ok(bytes) => a_bytes = bytes,
            Err(e)    => return Err("Invalid hex in parameter a".to_string()),
        }
        match b.from_hex() {
            Ok(bytes) => b_bytes = bytes,
            Err(e)    => return Err("Invalid hex in parameter b".to_string()),
        }
        let mut c = Vec::new();
        for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()){
            c.push(x^y);
        }
        Ok(c.as_slice().to_hex())
    }
}
