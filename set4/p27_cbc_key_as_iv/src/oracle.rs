use cbc;

use rand;

pub struct Oracle {
    key: [u8; 16],
}

impl Oracle {
    pub fn new() -> Oracle {
        Oracle {
            key: random_block(),
        }
    }
    #[cfg(test)]
    pub fn controlled(key : &[u8; 16]) -> Oracle {
        Oracle { key: key.clone() }
    }
    pub fn encrypt(&self, message: &str) -> Vec<u8> {
        cbc::aes_cbc_encrypt(message.as_bytes(), &self.key, &self.key)
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, DecryptError> {
        if let Ok(decoded) = cbc::aes_cbc_decrypt(&ciphertext, &self.key,
                                                  &self.key){
            if decoded.iter().any(|c| c > &127u8) {
                Err(DecryptError::BadAscii(decoded))
            }
            else {
                Ok(String::from_utf8(decoded).unwrap())
            }
        }
        else {
            Err(DecryptError::BadDecryption)
        }
    }
}

#[derive(Debug)]
pub enum DecryptError {
    BadDecryption,
    BadAscii(Vec<u8>),
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

#[cfg(test)]
mod tests {
    use super::Oracle;

    #[test]
    fn encrypt() {
        let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
                   0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
        let oracle = Oracle::controlled(&key);
        let output = oracle.encrypt("hello world");
        let expected = vec![0x72, 0xf7, 0x9d, 0x07, 0x11, 0x61, 0x92, 0x11, 0xac,
                            0x89, 0xe5, 0x19, 0xc0, 0x2e, 0x5e, 0x3f];
        assert_eq!(output, expected);
    }
}
