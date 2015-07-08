use aes;

use rand;

pub struct AesEcbOracle {
    key: [u8; 16],
    base_str: Vec<u8>,
    prefix: Vec<u8>,
}

impl AesEcbOracle {
    pub fn new(base_str: &[u8]) -> AesEcbOracle {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        for el in key.iter_mut() {
            *el = rng.gen::<u8>();
        }
        AesEcbOracle {
            key: key,
            base_str: Vec::from(base_str),
            prefix: AesEcbOracle::generate_prefix(),
        }
    }
    pub fn with_key(key : &[u8; 16], base_str: &[u8]) -> AesEcbOracle {
        AesEcbOracle {
            key: key.clone(),
            base_str: Vec::from(base_str),
            prefix: Vec::new()
        }
    }
    pub fn encrypt(&self, user_controlled: &[u8]) -> Vec<u8> {
        let text: Vec<u8> =
            self.prefix.iter().cloned().chain(
                user_controlled.iter().cloned()
            ).chain(
                self.base_str.iter().cloned()
            ).collect();
        aes::aes_ecb_encrypt(&text[..], &self.key)
    }
    fn generate_prefix() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let length = rng.gen::<u8>() as usize;
        let mut prefix = Vec::with_capacity(length);
        for _ in 0..length {
            prefix.push(rng.gen::<u8>());
        }
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::AesEcbOracle;

    #[test]
    fn empty_encrypt() {
        let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
                   0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
        let oracle = AesEcbOracle::with_key(&key, "hello world".as_bytes());
        let output = oracle.encrypt(&[]);
        let expected = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                        0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5, 0xeb];
        assert_eq!(&output[..], expected);
    }

    #[test]
    fn encrypt() {
        let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
                   0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
        let oracle = AesEcbOracle::with_key(&key, "world".as_bytes());
        let output = oracle.encrypt(&"hello ".as_bytes());
        let expected = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                        0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5, 0xeb];
        assert_eq!(&output[..], expected);
    }
}
