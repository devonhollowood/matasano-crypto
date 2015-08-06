use ctr;

use rand;

pub struct Oracle {
    key: [u8; 16],
    nonce: u64,
}

impl Oracle {
    pub fn new() -> Oracle {
        use rand::Rng;
        Oracle {
            key: random_block(),
            nonce: rand::thread_rng().gen::<u64>(),
        }
    }
    #[cfg(test)]
    pub fn controlled(key : &[u8; 16], nonce: u64) -> Oracle {
        Oracle { key: key.clone(), nonce: nonce }
    }
    pub fn encrypt(&self, message: &str) -> Vec<u8> {
        let mut encryptor = ctr::AesCtr::new(self.nonce, &self.key[..]);
        let prefix = "comment1=cooking%20MCs;userdata=";
        let message = message.replace("=", "%3D").replace(";", "%3B");
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let text: Vec<u8> =
            prefix.bytes().chain(message.bytes()).chain(suffix.bytes()).collect();
        encryptor.encrypt(&text[..]).unwrap()
    }
    pub fn is_admin(&self, ciphertext: &[u8]) -> bool {
        let mut decryptor = ctr::AesCtr::new(self.nonce, &self.key[..]);
        contains(&decryptor.decrypt(&ciphertext).unwrap()[..], b"user=admin")
    }
}
fn random_block() -> [u8; 16] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut block = [0u8; 16];
    for el in block.iter_mut() {
        *el = rng.gen::<u8>();
    }
    block
}

fn contains(container: &[u8], containee:  &[u8]) -> bool {
    for idx in 0..(container.len()-containee.len()) {
        if container[idx..].starts_with(containee) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::Oracle;

    #[test]
    fn empty_encrypt() {
        let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
                   0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
        let nonce = 24601;
        let oracle = Oracle::controlled(&key, nonce);
        let output = oracle.encrypt("");
        let expected = vec![0xb0, 0x72, 0xba, 0x51, 0x81, 0x12, 0x34, 0xeb, 0xf0,
                            0xd7, 0x94, 0xd2, 0x2a, 0x75, 0x06, 0xa7, 0x75, 0xc5,
                            0xf5, 0x1f, 0xe3, 0x60, 0xf7, 0xc7, 0x69, 0x22, 0x14,
                            0x91, 0x9d, 0x0f, 0xfa, 0x95, 0x65, 0xb9, 0x7f, 0xcd,
                            0x10, 0x33, 0x26, 0x45, 0x42, 0x47, 0xc3, 0xd7, 0xcd,
                            0x09, 0xfe, 0x8b, 0x73, 0xac, 0x03, 0x1d, 0xe2, 0x71,
                            0x6b, 0x1d, 0x5b, 0x3f, 0xa5, 0x75, 0xd4, 0x56, 0xe9,
                            0xb2, 0x6f, 0xd6, 0xef, 0xdd, 0x69, 0x76, 0x46, 0x0f,
                            0x31, 0x7e];
        assert_eq!(output, expected);
    }

    #[test]
    fn encrypt() {
        let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
                   0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
        let nonce = 24601;
        let oracle = Oracle::controlled(&key, nonce);
        let output = oracle.encrypt("hello world");
        let expected = vec![0xb0, 0x72, 0xba, 0x51, 0x81, 0x12, 0x34, 0xeb, 0xf0,
                            0xd7, 0x94, 0xd2, 0x2a, 0x75, 0x06, 0xa7, 0x75, 0xc5,
                            0xf5, 0x1f, 0xe3, 0x60, 0xf7, 0xc7, 0x69, 0x22, 0x14,
                            0x91, 0x9d, 0x0f, 0xfa, 0x95, 0x36, 0xbf, 0x7c, 0xcc,
                            0x12, 0x76, 0x3f, 0x5e, 0x02, 0x16, 0x82, 0xde, 0x9e,
                            0x0a, 0xfa, 0x8d, 0x73, 0xe7, 0x45, 0x1f, 0xbe, 0x71,
                            0x6b, 0x1d, 0x47, 0x39, 0xbb, 0x7e, 0x95, 0x41, 0xeb,
                            0xe3, 0x25, 0x82, 0xfa, 0x9f, 0x36, 0x61, 0x49, 0x08,
                            0x7b, 0x22, 0xe7, 0x42, 0xaa, 0x35, 0xd0, 0x8c, 0x68,
                            0x02, 0xc4, 0x00, 0x78];
        assert_eq!(output, expected);
    }

    use super::contains;

    #[test]
    fn contains_pass() {
        let container = vec![0,1,2,3,4];
        let containee = vec![2,3];
        assert_eq!(contains(&container[..], &containee[..]), true);
    }

    #[test]
    fn contains_fail() {
        let container = vec![0,1,2,3,4];
        let containee = vec![3,4,5];
        assert_eq!(contains(&container[..], &containee[..]), false);
    }
}
