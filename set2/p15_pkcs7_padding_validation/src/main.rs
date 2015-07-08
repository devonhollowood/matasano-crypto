fn valid_pkcs7_padding(bytes: &[u8]) -> bool {
    if let Some(last_byte) = bytes.last() {
        *last_byte != 0 &&
            bytes.len() >= *last_byte as usize &&
            bytes[(bytes.len() - *last_byte as usize)..].iter().all(|b| b==last_byte)
    }
    else {
        false
    }
}

#[test]
fn no_pad() {
    let test = "hello world".as_bytes();
    assert_eq!(valid_pkcs7_padding(test), false);
}

#[test]
fn zero_pad() {
    let test = "hello world\0".as_bytes();
    assert_eq!(valid_pkcs7_padding(test), false);
}

#[test]
fn short_pad() {
    let test = "hello world\x05\x05\x05\x05".as_bytes();
    assert_eq!(valid_pkcs7_padding(test), false);
}

#[test]
fn correct_pad() {
    let test = "hello world\x05\x05\x05\x05\x05".as_bytes();
    assert_eq!(valid_pkcs7_padding(test), true);
}

fn check(s: &str, expected: bool) {
    print!("Checking {:?}: ", s);
    match valid_pkcs7_padding(s.as_bytes()) == expected {
        true => println!("pass"),
        false => panic!("fail"),
    }
}

fn main() {
    check("ICE ICE BABY\x04\x04\x04\x04", true);
    check("ICE ICE BABY\x05\x05\x05\x05", false);
    check("ICE ICE BABY\x01\x02\x03\x04", false);
}
