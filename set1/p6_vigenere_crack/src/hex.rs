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

pub fn single_byte_xor(message: &[u8], byte: u8) -> Vec<u8> {
    use std::iter::repeat;
    let xor_bytes : Vec<u8> = repeat(byte).take(message.len()).collect();
    xor(message, &xor_bytes[..]).unwrap()
}

pub fn repeated_key_xor(message: &[u8], key: &[u8]) -> Vec<u8> {
    use std::iter::IteratorExt;
    let xor_bytes : Vec<u8> = key.iter().cloned().cycle().take(message.len())
        .collect();
    xor(message, &xor_bytes[..]).unwrap()
}

#[cfg(test)]
mod tests{
    use super::*;
    
    #[test]
    fn read_hex_test() {
        assert_eq!(read_hex("06ff3a"), Ok(vec![0x06u8, 0xffu8, 0x3au8]));
        assert!(read_hex("06f").is_err());
        assert!(read_hex("06ff3q").is_err());
    }

    #[test]
    fn display_hex_test() {
        assert_eq!(display_hex(&[0x06u8, 0xffu8, 0x3au8]), 
            String::from_str("06ff3a"));
    }

    #[test]
    fn xor_test() {
        let a = [0x06u8, 0xffu8, 0x3au8];
        let b = [0x89u8, 0x07u8, 0x18u8];
        let c = [0x38];
        assert_eq!(xor(&a, &b), Ok(vec![0x8fu8, 0xf8u8, 0x22u8]));
        assert!(xor(&a, &c).is_err());
    }
    
    #[test]
    fn single_byte_xor_test() {
        let message = read_hex("1b37373331363f78151b7f2b783431333d\
            78397828372d363c78373e783a393b3736").unwrap();
        let byte = 0x58u8;
        let res = "Cooking MC's like a pound of bacon".as_bytes();
        assert_eq!(single_byte_xor(&message[..], byte), res.to_vec());
    }

    #[test]
    fn repeated_key_xor_test() {
        let message = "Burning 'em, if you ain't quick and nimble".as_bytes();
        let key = "ICE".as_bytes();
        let res = read_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324\
            202d623d63343c2a26226324272765272a282b2f20").unwrap();
        assert_eq!(repeated_key_xor(&message[..], key), res.to_vec());
    }
}
