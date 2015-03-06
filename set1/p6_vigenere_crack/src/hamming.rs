pub fn hamming_dist(a: &[u8], b:&[u8]) -> Option<u32> {
    use std::iter::{IteratorExt, AdditiveIterator};
    if a.len()!=b.len() {
        return None;
    }
    let result = a.iter().zip(b.iter()).map(|(x,y)| {n_ones(x^y) as u32}).sum();
    Some(result)
}

pub fn avg_hamming_dist(entries: &[&[u8]]) -> Option<f32> {
    let n = entries.len();
    if n==0 {return None};
    let mut sum = 0f32;
    for idx_a in 0..n {
        for idx_b in (idx_a+1)..n {
            let a = entries[idx_a];
            let b = entries[idx_b];
            match hamming_dist(a, b) {
                Some(d) => sum += d as f32,
                None    => return None,
            }
        }
    }
    let nf32 = n as f32;
    Some(sum/(nf32*(nf32+1f32)/2f32))
}

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

    fn avg_hamming_dist_test() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();
        let c = "onyonghasayo!!".as_bytes();
        let d = "this is not a test".as_bytes();
        assert_eq!(avg_hamming_dist(&[a,b,c]),
            Some((hamming_dist(a,b).unwrap()
            + hamming_dist(b,c).unwrap()
            + hamming_dist(a,c).unwrap()) as f32/3f32));
        assert_eq!(avg_hamming_dist(&[a,b,c,d]), None);
    }
}
