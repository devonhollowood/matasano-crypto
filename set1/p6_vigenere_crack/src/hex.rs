extern crate "rustc-serialize" as serialize;

pub fn read_hex(text_hex: &str) -> Result<Vec<u8>, String> {
    use self::serialize::hex::FromHex;
    match text_hex.from_hex() {
        Ok(vec)  => Ok(vec),
        Err(e)   => Err(format!("{}", e)),
    }
}

pub fn display_hex(hex: &[u8]) -> String {
    use self::serialize::hex::ToHex;
    hex.to_hex()
}

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len()!=b.len() {
        return Err(format!("Lengths not equal: {} vs {}", a.len(), b.len()));
    }
    let mut c = Vec::new();
    for (&x, &y) in a.iter().zip(b.iter()){
        c.push(x^y);
    }
    Ok(c)
}

pub fn single_byte_xor(message: &[u8], byte: u8) -> Result<Vec<u8>, String> {
    use std::iter::repeat;
    let xor_bytes : Vec<u8> = repeat(byte).take(message.len()).collect();
    xor(message, &xor_bytes[..])
}

pub fn repeated_key_xor(message: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use std::iter::IteratorExt;
    let xor_bytes : Vec<u8> = key.iter().cloned().cycle().take(message.len())
        .collect();
    xor(message, &xor_bytes[..])
}
