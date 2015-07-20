mod twister;

use twister::Twister;

/// Given an `n` == `y ^ ((y << a) & b)`, finds `y`.
fn unshiftl(n: u32, a: u8, b: u32) -> u32 {
    //copy over known bits
    let mut mask = ((1u64 << a) - 1) as u32; //`a` ones, starting at the right
    let mut y = 0u32 ^ (n & mask); //copy the bytes left intact by the xor
    //get other bits one at a time, starting from the right
    for bit in a..32 { //`bit` is the location of the bit from the right
        mask = 1 << bit;
        let n_bit = n & mask; //n's bit, in the destination position
        let b_bit = b & mask; //b's bit, in the destination position
        let y_bit = (y & 1 << bit - a) << a; //y's bit, in the destination position
        y ^= n_bit ^ y_bit & b_bit; //copy over untempered bit
    }
    y
}

/// Given an `n` == `y ^ ((y >> a) & b)`, finds `y`.
fn unshiftr(n: u32, a: u8, b: u32) -> u32 {
    //copy over known bits
    let mut mask = 0xffffffff ^ 0xffffffff >> a; //`a` ones, starting at the left
    let mut y = 0u32 ^ (n & mask); //copy the bytes left intact by the xor
    //get other bits one at a time, starting from the left
    for bit in a..32 { //`bit` is the location of the bit from the left
        mask = 0x80000000 >> bit;
        //n's bit, in the destination position
        let n_bit = n & mask;
        //b's bit, in the destination position
        let b_bit = b & mask;
        //y's bit, in the destination position
        let y_bit = (y & 0x80000000 >> bit - a) >> a;
        y ^= n_bit ^ y_bit & b_bit; //copy over untempered bit
    }
    y
}

/// Reverses mt19937's tempering of `n`
fn untemper(n: u32) -> u32 {
        let mut y = unshiftr(n, 18, 0xffffffff);
        y = unshiftl(y, 15, 0xefc60000);
        y = unshiftl(y, 7, 0x9d2c5680);
        y = unshiftr(y, 11, 0xffffffff);
        y
}

/// Clones a mt19937 given 624 outputs corresponding to a full state
pub fn clone_twister(outputs: &[u32; 624]) -> Twister{
    let mut state = [0u32; 624];
    for idx in 0..624 {
        state[idx] = untemper(outputs[idx]);
    }
    Twister::raw(0, &state)
}

#[test]
fn it_works() {
    let mut t1 = Twister::new(24601);
    let mut outputs = [0u32; 624];
    for idx in 0..624 {
        outputs[idx] = t1.next().unwrap();
    }
    let mut clone = clone_twister(&outputs);
    assert_eq!(clone.next(), t1.next());
}

#[cfg(test)]
mod tests {
    fn unshiftl_test(y: u32, a: u8, b: u32) {
        println!("Running unshiftl_test({:x}, {:x}, {:x})", y, a, b);
        let n = y ^ y << a & b;
        println!("n = {:x}", n);
        assert_eq!(y, super::unshiftl(n, a, b));
    }

    #[test]
    fn unshiftl_tests() {
        unshiftl_test(0, 0, 0);
        unshiftl_test(0xffffffff, 8, 0xffffffff);
        unshiftl_test(0x1337c0de, 15, 0xefc60000);
        unshiftl_test(24601, 7, 0x9d2c5680);
    }

    fn unshiftr_test(y: u32, a: u8, b: u32) {
        println!("Running unshiftr_test({:x}, {:x}, {:x})", y, a, b);
        let n = y ^ y >> a & b;
        println!("n = {:x}", n);
        assert_eq!(y, super::unshiftr(n, a, b));
    }

    #[test]
    fn unshiftr_tests() {
        unshiftr_test(0, 0, 0);
        unshiftr_test(0xffffffff, 8, 0xffffffff);
        unshiftr_test(0x1337c0de, 15, 0xefc60000);
        unshiftr_test(24601, 7, 0x9d2c5680);
    }

    fn temper(mut y: u32) -> u32 {
        y ^= y >> 11;
        y ^= y << 7 & 0x9d2c5680;
        y ^= y << 15 & 0xefc60000;
        y ^= y >> 18;
        y
    }

    fn untemper_test(n: u32){
        println!("Running untemper_test({:x})", n);
        let y = temper(n);
        println!("y = {:x}", y);
        assert_eq!(n, super::untemper(y));
    }

    #[test]
    fn untemper() {
        untemper_test(0);
        untemper_test(24601);
        untemper_test(0xffffffff);
        untemper_test(0x1337c0de);
    }
}
