use twister;

pub struct Encryptor {
    stream: TwisterStream,
}

impl Encryptor {
    pub fn new(seed: u16) -> Encryptor {
        Encryptor { stream: TwisterStream::new(seed) }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.iter().map(|b| b ^ self.stream.next().unwrap()).collect()
    }
}

pub struct Decryptor {
    stream: TwisterStream,
}

impl Decryptor {
    pub fn new(seed: u16) -> Decryptor {
        Decryptor { stream: TwisterStream::new(seed) }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.iter().map(|b| b ^ self.stream.next().unwrap()).collect()
    }
}

#[cfg(test)]
mod stream_cipher_tests {
    use super::{Encryptor, Decryptor};

    #[test]
    fn encryptor_new() {
        let e = Encryptor::new(24601);
        assert_eq!(e.stream.current, 0xcbb6cbb6);
        assert_eq!(e.stream.idx, 0);
    }

    #[test]
    fn encrypt() {
        let mut e = Encryptor::new(24601);
        let encrypted = e.encrypt(&"It was love at first sight.".as_bytes()[..]);
        let expected = vec![0x82, 0xc2, 0xeb, 0xc1, 0xea, 0xae, 0x14, 0xbe,
                            0xf9, 0xab, 0x55, 0x58, 0x0c, 0xea, 0xf4, 0xdd,
                            0x29, 0xa5, 0x77, 0xa4, 0x2b, 0xbe, 0x6f, 0x42,
                            0xd7, 0x03, 0x17];
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn decryptor_new() {
        let d = Decryptor::new(24601);
        assert_eq!(d.stream.current, 0xcbb6cbb6);
        assert_eq!(d.stream.idx, 0);
    }

    #[test]
    fn decrypt() {
        let mut d = Decryptor::new(24601);
        let ciphertext = vec![0x82, 0xc2, 0xeb, 0xc1, 0xea, 0xae, 0x14, 0xbe,
                              0xf9, 0xab, 0x55, 0x58, 0x0c, 0xea, 0xf4, 0xdd,
                              0x29, 0xa5, 0x77, 0xa4, 0x2b, 0xbe, 0x6f, 0x42,
                              0xd7, 0x03, 0x17];
        let decrypted = d.decrypt(&ciphertext[..]);
        let expected = "It was love at first sight.".as_bytes();
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn identity() {
        let mut e = Encryptor::new(22);
        let mut d = Decryptor::new(22);
        let plaintext = b"The first time Yossarian saw the chaplain, \
                          he fell madly in love with him.".to_vec();
        let encrypted = e.encrypt(&plaintext[..]);
        let decrypted = d.decrypt(&encrypted[..]);
        assert_eq!(plaintext, decrypted);
    }
}

struct TwisterStream {
    twister: twister::Twister, //underlying mt19937
    current: u32, //most recent output from twister
    idx: u8, //which byte within `current` to return next
}

impl TwisterStream {
    fn new(seed: u16) -> TwisterStream {
        let mut t = twister::Twister::new(seed as u32);
        let current = t.next().unwrap();
        TwisterStream { twister: t, current: current, idx: 0 }
    }
}

impl Iterator for TwisterStream {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        //set up mask to get `idx`th byte from `current`
        let mask = 0xff000000 >> 8 * self.idx;
        //get `idx`th byte from `current`
        let byte = ((self.current & mask) >> 8 * (3 - self.idx)) as u8;
        //update `idx` and `current` (if necessary)
        self.idx += 1;
        if self.idx == 4 { //if at end of current
            self.idx = 0;
            self.current = self.twister.next().unwrap();
        }
        Some(byte)
    }
}

#[cfg(test)]
mod twister_stream_tests {
    use super::TwisterStream;

    #[test]
    fn new() {
        let t = TwisterStream::new(24601);
        assert_eq!(t.current, 0xcbb6cbb6);
        assert_eq!(t.idx, 0);
    }

    #[test]
    fn next() {
        let mut t = TwisterStream::new(24601);
        assert_eq!(t.next().unwrap(), 0xcb);
        assert_eq!(t.next().unwrap(), 0xb6);
        assert_eq!(t.next().unwrap(), 0xcb);
        assert_eq!(t.next().unwrap(), 0xb6);
        assert_eq!(t.next().unwrap(), 0x8b);
    }
}
