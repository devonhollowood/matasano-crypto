use md4;
use bits;

///Secret-prefix MD4 MAC
pub struct Md4Mac {
    key: Vec<u8>,
}

impl Md4Mac {

    ///Creates a new Md4Mac with given key
    pub fn new(key: &[u8]) -> Md4Mac {
        Md4Mac { key: key.to_vec() }
    }

    ///Prepends secret key to `bytes` and then hashes
    pub fn hash(&self, bytes: &[u8]) -> [u8; 16] {;
        let input = self.key.iter().cloned().chain(bytes.iter().cloned())
                        .collect::<Vec<u8>>();
        md4::md4(&input[..])
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
    use super::Md4Mac;

    #[test]
    fn new() {
        let mac = Md4Mac::new(b"yellow submarine");
        assert_eq!(mac.key, b"yellow submarine".to_vec());
    }

    #[test]
    fn hash() {
        let mac = Md4Mac::new(b"yellow submarine");
        let hash = mac.hash(b"in the town where i was born");
        let expected = [0x7f, 0x26, 0x3f, 0x8c, 0xea, 0x65, 0x28, 0xd5,
                        0x7f, 0xc7, 0x8d, 0xa5, 0xe5, 0xeb, 0x27, 0xb6];
        assert_eq!(hash, expected);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_message() {
        let mac = Md4Mac::new(b"yellow submarine");
        let hash_a = mac.hash(b"in the town where i was born");
        let hash_b = mac.hash(b"in the town where I was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    #[should_panic(expected="assertion failed")]
    fn hash_different_keys() {
        let mac_a = Md4Mac::new(b"yellow submarine");
        let hash_a = mac_a.hash(b"in the town where i was born");
        let mac_b = Md4Mac::new(b"octopus's garden");
        let hash_b = mac_b.hash(b"in the town where i was born");
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn validate() {
        let mac = Md4Mac::new(b"yellow submarine");
        let hash = [0x7f, 0x26, 0x3f, 0x8c, 0xea, 0x65, 0x28, 0xd5,
                    0x7f, 0xc7, 0x8d, 0xa5, 0xe5, 0xeb, 0x27, 0xb6];
        assert!(mac.validate(b"in the town where i was born", &hash));
    }
}
