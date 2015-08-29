extern crate crypto;

pub fn insecure_compare(first: &[u8], second: &[u8]) -> bool {
    for (x, y) in first.iter().zip(second.iter()) {
        if { x != y } { return false; }
        std::thread::sleep_ms(50);
    }
    true
}

pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 20] {
    use std::iter::repeat;
    //get key to correct length
    let prepared_key = prepare_key(key);
    let outer_pad: Vec<u8> =
        repeat(0x5c).zip(prepared_key.iter()).map(|(x, y)| x ^ y).collect();
    let inner_pad: Vec<u8> =
        repeat(0x36).zip(prepared_key.iter()).map(|(x, y)| x ^ y).collect();
    let inner: Vec<u8> = inner_pad.iter().chain(message.iter()).cloned()
                                  .collect();
    let outer: Vec<u8> = outer_pad.iter().chain(sha1(&inner[..]).iter())
                                  .cloned().collect();
    sha1(&outer[..])
}

///SHA1 of `input`
pub fn sha1(input: &[u8]) -> [u8; 20] {
    use crypto::digest::Digest;
    use crypto::sha1::Sha1;
    let mut hasher = Sha1::new();
    hasher.input(input);
    let mut output = [0; 20];
    hasher.result(& mut output[..]);
    output
}

///Prepares key for HMAC-SHA1
fn prepare_key(key: &[u8]) -> [u8; 64] {
    use std::io::Write;
    const BLOCKSIZE: usize = 64;
    let mut prepared_key = [0; 64];
    if key.len() <= BLOCKSIZE { //zero-pad key
        (&mut prepared_key[..]).write_all(key).unwrap();
    }
    else if key.len() > BLOCKSIZE { //hash key
        (&mut prepared_key[..]).write_all(&sha1(key)[..]).unwrap();
    }
    prepared_key
}

#[test]
fn it_works() {
}

#[cfg(test)]
mod tests {

    #[test] #[ignore]
    fn insecure_compare() {
        assert!(super::insecure_compare(b"yellow submarine", b"yellow submarine"),
            "should have been equal");
        assert!(!super::insecure_compare(b"yellow submarine", b"yellow_submarine"),
            "should have been unequal");
    }

    #[test]
    fn hmac() {
        let key = b"yellow submarine";
        let message = b"In the town / where I was born / there lived a man / \
                        who sailed to sea";
        let expected = [0x7f, 0x58, 0xc4, 0xf7, 0xc7, 0x94, 0xba, 0xa2, 0x5e,
                        0xcd, 0xbe, 0x90, 0x19, 0x1e, 0x45, 0xe3, 0x5e, 0xd6,
                        0x99, 0xff];
        assert_eq!(super::hmac(key, message), expected);
    }

    #[test]
    fn sha1() {
        let expected = [0xda, 0x03, 0x5e, 0x50, 0x1d, 0xef, 0x35, 0x4e, 0xc3,
                        0x12, 0x5f, 0x4b, 0xb1, 0x28, 0xeb, 0x3d, 0xfb, 0x28,
                        0x42, 0xb7];
        assert_eq!(super::sha1(b"yellow submarine"), expected);
    }

    #[test]
    fn prepare_key() {
        //short key
        assert_eq!(&super::prepare_key(b"yellow submarine")[..],
                   &b"yellow submarine\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..]);
        //long key
        let long_input = b"In the town / where I was born / there lived a man / \
                           who sailed the seas";
        let long_expected = [0xf5, 0xc1, 0x17, 0xa6, 0xcf, 0x2e, 0xea, 0x95,
                             0xef, 0x99, 0x06, 0x3e, 0xe9, 0x9e, 0x2d, 0x27,
                             0x9d, 0x6a, 0xbb, 0x79, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(&super::prepare_key(long_input)[..], &long_expected[..]);
        //64-byte key
        let exact_key = b"yellow submarineyellow submarineyellow submarine\
                          yellow submarine";
        assert_eq!(&super::prepare_key(exact_key)[..], &exact_key[..]);
    }
}
