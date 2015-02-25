extern crate "rustc-serialize" as serialize;

pub fn hex_to_ascii(text_hex: &str) -> Result<String, String> {
    use self::serialize::hex::{FromHex, ToHex};
    use std::string::FromUtf8Error;
    let utf8 : Vec<u8>;
    match text_hex.from_hex() {
        Ok(vec)  => utf8 = vec,
        Err(e)   => return Err(format!("{}", e)),
    }
    match String::from_utf8(utf8) {
        Ok(s)  => Ok(s),
        Err(e) => Err(format!("{}", e.utf8_error())),
    }
}

pub fn xor(a_hex: &str, b_hex: &str) -> Result<String, String> {
    use self::serialize::hex::{FromHex, ToHex};
    if a_hex.len()!=b_hex.len() {return Err("Lengths not equal".to_string());}
    let a_bytes : Vec<u8>;
    let b_bytes : Vec<u8>;
    match a_hex.from_hex() {
        Ok(bytes) => a_bytes = bytes,
        Err(_)    => return Err("Invalid hex in parameter a".to_string()),
    }
    match b_hex.from_hex() {
        Ok(bytes) => b_bytes = bytes,
        Err(_)    => return Err("Invalid hex in parameter b".to_string()),
    }
    let mut c = Vec::new();
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()){
        c.push(x^y);
    }
    Ok(c[..].to_hex())
}

pub fn single_byte_xor(text_hex: &str, byte: u8) -> Result<String, String> {
    use self::serialize::hex::ToHex;
    use std::iter::repeat;
    let xor_bytes : Vec<u8> = repeat(byte).take(text_hex.len()/2).collect();
    xor(&xor_bytes[..].to_hex()[..], text_hex)
}
