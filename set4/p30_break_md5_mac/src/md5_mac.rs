///Secret-prefix SHA-1 MAC
pub struct Md5Mac {
    key: Vec<u8>,
}

impl Md5Mac {

    ///Creates a new Md5Mac with given key
    pub fn new(key: &[u8]) -> Md5Mac {
        Md5Mac { key: key.to_vec() }
    }

    ///Prepends secret key to `bytes` and then hashes
    pub fn hash(&self, bytes: &[u8]) -> [u8; 16] {
        use crypto::digest::Digest;
        use crypto::md5::Md5;
        let mut hasher = Md5::new();
        let input = self.key.iter().cloned().chain(bytes.iter().cloned())
                        .collect::<Vec<u8>>();
        hasher.input(&input[..]);
        let mut output = [0; 16];
        hasher.result(& mut output[..]);
        output
    }

    ///Convenience function, which returns string representation of `hash(bytes)`
    pub fn hash_str(&self, bytes: &[u8]) -> String {
        use crypto::digest::Digest;
        use crypto::md5::Md5;
        let mut hasher = Md5::new();
        let input = self.key.iter().cloned().chain(bytes.iter().cloned())
                        .collect::<Vec<u8>>();
        hasher.input(&input[..]);
        hasher.result_str()
    }

    ///True if the hash of `message` prepended with the secret key is equal to
    ///`hash`, otherwise false
    pub fn validate(&self, message: &[u8], hash: &[u8; 16]) -> bool {
        let message_hash = self.hash(message);
        message_hash == *hash
    }
}

#[cfg(test)]
mod tests {
    use super::Md5Mac;

    #[test]
    fn new() {
        let mac = Md5Mac::new(b"yellow submarine");
        assert_eq!(mac.key, b"yellow submarine".to_vec());
    }

    #[test]
    fn hash() {
        let mac = Md5Mac::new(b"yellow submarine");
        let hash = mac.hash(b"in the town where i was born");
        let expected = [0x47, 0xef, 0x41, 0x6a, 0xa4, 0xbb, 0xcb, 0x98,
                        0x38, 0xba, 0x09, 0xb5, 0xe0, 0x9c, 0x45, 0x16];
        assert_eq!(hash, expected);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_message() {
        let mac = Md5Mac::new(b"yellow submarine");
        let hash_a = mac.hash(b"in the town where i was born");
        let hash_b = mac.hash(b"in the town where I was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_keys() {
        let mac_a = Md5Mac::new(b"yellow submarine");
        let hash_a = mac_a.hash(b"in the town where i was born");
        let mac_b = Md5Mac::new(b"octopus's garden");
        let hash_b = mac_b.hash(b"in the town where i was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn hash_str() {
        let mac = Md5Mac::new(b"yellow submarine");
        let hash = mac.hash_str(b"in the town where i was born");
        let expected = String::from("47ef416aa4bbcb9838ba09b5e09c4516");
        assert_eq!(hash, expected);
    }

    #[test]
    fn validate() {
        let mac = Md5Mac::new(b"yellow submarine");
        let hash = [0x47, 0xef, 0x41, 0x6a, 0xa4, 0xbb, 0xcb, 0x98,
                    0x38, 0xba, 0x09, 0xb5, 0xe0, 0x9c, 0x45, 0x16];
        assert!(mac.validate(b"in the town where i was born", &hash));
    }
}
