use twister;

pub struct TwisterStream {
    twister: twister::Twister, //underlying mt19937
    current: u32, //most recent output from twister
    idx: u8, //which byte within `current` to return next
}

impl TwisterStream {
    pub fn new(seed: u16) -> TwisterStream {
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
