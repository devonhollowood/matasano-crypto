use rand::{thread_rng, Rng};
use ctr::AesCtr;

pub struct Oracle {
    key: [u8; 16],
    nonce: u64,
}

impl Oracle {
    pub fn new() -> Oracle {
        Oracle { key: Oracle::random_key(), nonce: Oracle::random_nonce() }
    }

    #[cfg(test)]
    fn controlled(key: [u8; 16], nonce: u64) -> Oracle {
        Oracle { key: key, nonce: nonce }
    }

    fn random_key() -> [u8; 16] {
        let mut key = [0u8; 16];
        let mut rng = thread_rng();
        for el in key.iter_mut() {
            *el = rng.gen();
        }
        key
    }

    fn random_nonce() -> u64 {
        thread_rng().gen()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut encryptor = AesCtr::new(self.nonce, &self.key[..]);
        encryptor.encrypt(plaintext).unwrap()
    }

    pub fn edit(&self, ciphertext: &[u8], offset: usize, new_text: &[u8])
        -> Vec<u8> {
        let mut decryptor = AesCtr::new(self.nonce, &self.key[..]);
        let mut plaintext = decryptor.decrypt(ciphertext).unwrap();
        //if possible, just truncate plaintext and append new_text
        if offset + new_text.len() >= ciphertext.len() {
            plaintext.truncate(offset);
            plaintext.extend(new_text.to_vec());
        }
        //otherwise, do in-place mutation
        else {
            for idx in 0..new_text.len() {
                plaintext[idx+offset] = new_text[idx];
            }
        }
        self.encrypt(&plaintext[..])
    }
}

#[cfg(test)]
mod tests {
    use super::Oracle;

    #[test]
    fn encrypt() {
        let oracle = Oracle::controlled(*b"yellow submarine", 0x1337cafec0ded00d);
        let message = "It was love at first sight.".as_bytes();
        let ciphertext = oracle.encrypt(&message[..]);
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn edit_beginning() {
        let oracle = Oracle::controlled(*b"yellow submarine", 0x1337cafec0ded00d);
        let message_a = "What is love?".as_bytes();
        let ciphertext_a = oracle.encrypt(&message_a[..]);
        let ciphertext_b = oracle.edit(&ciphertext_a[..], 0,
                                       b"It was love at first sight.");
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];
        assert_eq!(ciphertext_b, expected);
    }

    #[test]
    fn edit_within() {
        let oracle = Oracle::controlled(*b"yellow submarine", 0x1337cafec0ded00d);
        let message_a = "It was like at first sight.".as_bytes();
        let ciphertext_a = oracle.encrypt(&message_a[..]);
        let ciphertext_b = oracle.edit(&ciphertext_a[..], 7, b"love");
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];
        assert_eq!(ciphertext_b, expected);
    }

    #[test]
    fn edit_near_end() {
        let oracle = Oracle::controlled(*b"yellow submarine", 0x1337cafec0ded00d);
        let message_a = "It was love?".as_bytes();
        let ciphertext_a = oracle.encrypt(&message_a[..]);
        let ciphertext_b = oracle.edit(&ciphertext_a[..], 11,
                                       b" at first sight.");
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];
        assert_eq!(ciphertext_b, expected);
    }

    #[test]
    fn edit_at_end() {
        let oracle = Oracle::controlled(*b"yellow submarine", 0x1337cafec0ded00d);
        let message_a = "It was love".as_bytes();
        let ciphertext_a = oracle.encrypt(&message_a[..]);
        let ciphertext_b = oracle.edit(&ciphertext_a[..], 11,
                                       b" at first sight.");
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];
        assert_eq!(ciphertext_b, expected);
    }
}
