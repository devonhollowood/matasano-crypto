use aes;

struct BlockStream {
    nonce: u64,
    ctr: u64,
}

impl BlockStream {
    fn new(nonce: u64) -> BlockStream {
        BlockStream { nonce: nonce, ctr: 0 }
    }

    fn to_bytes(&self) -> [u8; 16] {
        let mut bs = [0u8; 16];
        let nonce_bytes = bytes(self.nonce);
        for idx in 0..8 {
            bs[idx] = nonce_bytes[idx];
        }
        let ctr_bytes = bytes(self.ctr);
        for idx in 0..8 {
            bs[idx+8] = ctr_bytes[idx];
        }
        bs
    }
}

impl Iterator for BlockStream {
    type Item = [u8; 16];
    fn next(&mut self) -> Option<[u8; 16]> {
        if self.ctr == u64::max_value() {
            None
        }
        else {
            let next = self.to_bytes();
            self.ctr += 1;
            Some(next)
        }
    }
}

//u64 bytes in little-endian order
fn bytes(n: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8]; //storage for final bytes
    let mut mask = 0x00000000000000ff; //mask to select out bytes
    let mut shift = 0; //how much to left shift results
    for el in bytes.iter_mut() {
        *el = ((n & mask) >> shift) as u8; //get bytes
        mask <<= 8; //update mask
        shift += 8; //update shift
    }
    bytes
}

#[test]
fn bytes_test() {
    let n = 0x1337cafec0ded00d;
    assert_eq!(bytes(n), [0x0d, 0xd0, 0xde, 0xc0, 0xfe, 0xca, 0x37, 0x13]);
}

#[derive(Debug)]
pub enum AesCtrError {
    ExpiredNonce,
}

pub struct AesCtr {
    key: Vec<u8>,
    blocks: BlockStream,
}

impl AesCtr {
    pub fn new(nonce: u64, key: &[u8]) -> AesCtr {
        AesCtr{ key: key.to_vec(), blocks: BlockStream::new(nonce) }
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, AesCtrError> {
        let mut encrypted = Vec::new();
        let mut msg_itr = message.iter();
        //TODO: consider resturcturing this
        'outer: loop {
            if let Some(block_bytes) = self.blocks.next() {
                let aes_bytes = aes::aes_ecb_encrypt(&block_bytes[..],
                                                     &self.key[..]).unwrap();
                for aes_byte in aes_bytes {
                    if let Some(msg_byte) = msg_itr.next() {
                        encrypted.push(aes_byte ^ msg_byte);
                    }
                    else {
                        break 'outer;
                    }
                }
            }
            else {
                return Err(AesCtrError::ExpiredNonce);
            }
        }
        Ok(encrypted)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AesCtrError> {
        self.encrypt(ciphertext) //symmetric encryption/decryption is pretty cool
    }
}

#[cfg(test)]
mod blockstream_tests{
    use super::BlockStream;

    #[test]
    fn new() {
        let b = BlockStream::new(24601);
        assert_eq!(b.nonce, 24601);
        assert_eq!(b.ctr, 0);
    }

    #[test]
    fn to_bytes() {
        let b = BlockStream::new(0x1337cafec0ded00d);
        let expected = [0x0d, 0xd0, 0xde, 0xc0, 0xfe, 0xca, 0x37, 0x13,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(b.to_bytes(), expected);
    }

    #[test]
    fn next() {
        let mut b = BlockStream::new(0x1337cafec0ded00d);
        let expected0 = [0x0d, 0xd0, 0xde, 0xc0, 0xfe, 0xca, 0x37, 0x13,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(b.next().unwrap(), expected0);
        let expected1 = [0x0d, 0xd0, 0xde, 0xc0, 0xfe, 0xca, 0x37, 0x13,
                        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(b.next().unwrap(), expected1);
    }

}

#[cfg(test)]
mod aesctr_tests{
    use super::AesCtr;

    #[test]
    fn new() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let ctr = AesCtr::new(0x1337cafec0ded00d, &key[..]);
        assert_eq!(ctr.key, key);
        assert_eq!(ctr.blocks.nonce, 0x1337cafec0ded00d);
        assert_eq!(ctr.blocks.ctr, 0);
    }

    #[test]
    fn encrypt() {
        let key = "yellow submarine".as_bytes();
        let mut ctr = AesCtr::new(0x1337cafec0ded00d, &key[..]);
        let message = "It was love at first sight.".as_bytes();
        let output = ctr.encrypt(&message[..]).unwrap();
        let expected = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                            0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                            0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                            0x09, 0xd8, 0x9e];

        assert_eq!(&output[..], &expected[..])
    }

    #[test]
    fn decrypt() {
        let key = "yellow submarine".as_bytes();
        let mut ctr = AesCtr::new(0x1337cafec0ded00d, &key[..]);
        let ciphertext = vec![0x07, 0x2c, 0xfa, 0xaa, 0x89, 0x8b, 0xe4, 0x5c,
                              0xde, 0xb5, 0xf6, 0x6f, 0x74, 0xac, 0xde, 0xc8,
                              0x00, 0xdd, 0xa0, 0x5c, 0x9a, 0x49, 0x1b, 0x9f,
                              0x09, 0xd8, 0x9e];
        let output = ctr.decrypt(&ciphertext[..]).unwrap();
        let expected = "It was love at first sight.".as_bytes();
        assert_eq!(&output[..], &expected[..])
    }
}
