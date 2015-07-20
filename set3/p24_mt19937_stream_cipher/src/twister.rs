use std::iter::Iterator;

pub struct Twister {
    index: usize,
    state: [u32; 624],
}

impl Twister {
    pub fn new(seed: u32) -> Twister {
        let mut state = [0u32; 624];
        state[0] = seed;
        for idx in 1..state.len() {
            state[idx] = (0x6c078965*(state[idx-1] ^ (state[idx-1] >> 30)) as u64
                          + idx as u64 & 0xffffffff) as u32;
        }
        Twister { index: 0, state: state }
    }

    pub fn raw(index: usize, state: &[u32; 624]) -> Twister {
        Twister { index: index, state: *state.clone() }
    }

    fn generate_numbers(&mut self) {
        for idx in 0..self.state.len() {
            let y = (self.state[idx] & 0x80000000) +
                    (self.state[(idx + 1) % self.state.len()] & 0x7fffffff);
            self.state[idx] = self.state[(idx + 397) % self.state.len()] ^ (y >> 1);
            if y % 2 != 0 {
                self.state[idx] ^= 0x9908b0df;
            }
        }
    }
}

impl Iterator for Twister {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.index == 0 {
            self.generate_numbers();
        }
        let mut y = self.state[self.index];
        y ^= y >> 11;
        y ^= y << 7 & 0x9d2c5680;
        y ^= y << 15 & 0xefc60000;
        y ^= y >> 18;
        self.index = (self.index + 1) % self.state.len();
        Some(y)
    }
}

#[cfg(test)]
mod tests {
    use super::Twister;

    #[test]
    fn new_0() {
        let t = Twister::new(0);
        assert_eq!(t.index, 0);
        assert_eq!(t.state[0], 0);
    }

    #[test]
    fn first_10_0() {
        let t = Twister::new(0);
        let first_10 = t.take(10).collect::<Vec<u32>>();
        let expected = vec![0x8c7f0aac, 0x97c4aa2f, 0xb716a675, 0xd821ccc0,
                            0x9a4eb343, 0xdba252fb, 0x8b7d76c3, 0xd8e57d67,
                            0x6c74a409, 0x9fa1ded3];
        assert_eq![first_10, expected];
    }

    #[test]
    fn first_10_24601() {
        let t = Twister::new(24601);
        let first_10 = t.take(10).collect::<Vec<u32>>();
        let expected = vec![0xcbb6cbb6, 0x8bdd34d2, 0x96dd3078, 0x6d9ed4bb,
                            0x40d704d0, 0x0bcd0625, 0xbf7739dc, 0x51019dcb,
                            0xdd41362f, 0x3a88e7e6];
        assert_eq![first_10, expected];
    }

    #[test]
    fn skip_1000_0() {
        let t = Twister::new(0);
        let skip_1000 = t.skip(1000).take(10).collect::<Vec<u32>>();
        let expected = vec![0x4f751e27, 0x471c2cea, 0x5f7f367b, 0xe515c11c,
                            0x86647698, 0x06ca2e92, 0xc026fec3, 0xa029b8ac,
                            0x5560bed3, 0x545ce92d];
        assert_eq![skip_1000, expected];
    }
}
