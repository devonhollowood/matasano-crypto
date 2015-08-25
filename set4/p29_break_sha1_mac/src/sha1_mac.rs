#![allow(dead_code)]

///Secret-prefix SHA-1 MAC
pub struct Sha1Mac {
    key: Vec<u8>,
}

impl Sha1Mac {

    ///Creates a new Sha1Mac with given key
    pub fn new(key: &[u8]) -> Sha1Mac {
        Sha1Mac { key: key.to_vec() }
    }

    ///Prepends secret key to `bytes` and then hashes
    pub fn hash(&self, bytes: &[u8]) -> [u8; 20] {
        use crypto::digest::Digest;
        use crypto::sha1::Sha1;
        let mut hasher = Sha1::new();
        let input = self.key.iter().cloned().chain(bytes.iter().cloned())
                        .collect::<Vec<u8>>();
        hasher.input(&input[..]);
        let mut output = [0; 20];
        hasher.result(& mut output[..]);
        output
    }

    ///Convenience function, which returns string representation of `hash(bytes)`
    pub fn hash_str(&self, bytes: &[u8]) -> String {
        use crypto::digest::Digest;
        use crypto::sha1::Sha1;
        let mut hasher = Sha1::new();
        let input = self.key.iter().cloned().chain(bytes.iter().cloned())
                        .collect::<Vec<u8>>();
        hasher.input(&input[..]);
        hasher.result_str()
    }

    ///True if the hash of `message` prepended with the secret key is equal to
    ///`hash`, otherwise false
    pub fn validate(&self, message: &[u8], hash: &[u8; 20]) -> bool {
        let message_hash = self.hash(message);
        message_hash == *hash
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1Mac;

    #[test]
    fn new() {
        let mac = Sha1Mac::new(b"yellow submarine");
        assert_eq!(mac.key, b"yellow submarine".to_vec());
    }

    #[test]
    fn hash() {
        let mac = Sha1Mac::new(b"yellow submarine");
        let hash = mac.hash(b"in the town where i was born");
        let expected = [0x4e, 0x9e, 0x03, 0xea, 0x4d, 0x8e, 0x8c, 0x66, 0x5c,
                        0x7f, 0x75, 0x67, 0xfc, 0x73, 0xf5, 0x2a, 0xed, 0x9a,
                        0xbd, 0x3c];
        assert_eq!(hash, expected);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_message() {
        let mac = Sha1Mac::new(b"yellow submarine");
        let hash_a = mac.hash(b"in the town where i was born");
        let hash_b = mac.hash(b"in the town where I was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_keys() {
        let mac_a = Sha1Mac::new(b"yellow submarine");
        let hash_a = mac_a.hash(b"in the town where i was born");
        let mac_b = Sha1Mac::new(b"octopus's garden");
        let hash_b = mac_b.hash(b"in the town where i was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn hash_str() {
        let mac = Sha1Mac::new(b"yellow submarine");
        let hash = mac.hash_str(b"in the town where i was born");
        let expected = String::from("4e9e03ea4d8e8c665c7f7567fc73f52aed9abd3c");
        assert_eq!(hash, expected);
    }

    #[test]
    fn validate() {
        let mac = Sha1Mac::new(b"yellow submarine");
        let hash = [0x4e, 0x9e, 0x03, 0xea, 0x4d, 0x8e, 0x8c, 0x66, 0x5c,
                    0x7f, 0x75, 0x67, 0xfc, 0x73, 0xf5, 0x2a, 0xed, 0x9a,
                    0xbd, 0x3c];
        assert!(mac.validate(b"in the town where i was born", &hash));
    }
}
