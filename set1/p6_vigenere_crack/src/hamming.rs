fn n_ones(n : u8) -> u8 {
    let mut ones=0;
    let mut val=n;
    while val != 0 {
        ones += 1;
        val &= val-1;
    }
    ones
}

#[test]
fn n_ones_test() {
    assert_eq!(n_ones(5), 2);
}

pub fn hamming_dist(a: &[u8], b:&[u8]) -> Option<u32> {
    use std::iter::{IteratorExt, AdditiveIterator};
    if a.len()!=b.len() {
        return None;
    }
    let result = a.iter().zip(b.iter()).map(|(x,y)| {n_ones(x^y) as u32}).sum();
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_dist_test() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();
        let c = "this is not a test".as_bytes();
        assert_eq!(Some(37), hamming_dist(a,b));
        assert_eq!(None, hamming_dist(a,c));
    }
}
