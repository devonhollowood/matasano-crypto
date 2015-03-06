mod hex;
mod hamming;
mod score;

pub fn vigenere_crack(encoded: &[u8]) -> Option<Vec<u8>> {
    let blocksize = determine_blocksize(encoded);
    let transpose = transpose(encoded, blocksize);
    let mut result = Vec::with_capacity(blocksize as usize);
    for v in transpose {
        match single_byte_crack(&v[..]) {
            Some(byte) => result.push(byte),
            None       => return None,
        }
    }
    Some(result)
}

pub fn single_byte_crack(encoded: &[u8]) -> Option<u8> {
    use std::iter::range_inclusive;
    let mut min_score = 0f32;
    let mut min_byte = 0u8;
    for byte in range_inclusive(0u8, 255u8) {
        let hex = &hex::single_byte_xor(encoded, byte)[..];
        let answer;
        println!("{:?}", hex); //debug
        match std::str::from_utf8(hex) {
            Ok(s)  => answer = s,
            Err(_) => continue,
        }
        let score = score::score(answer);
        if score<min_score || min_score==0f32 {
            min_score = score;
            min_byte = byte;
        }
    }
    if min_score==0f32 {None}
    else {Some(min_byte)}
}



fn transpose(encoded: &[u8], blocksize: u8) -> Vec<Vec<u8>> {
    use std::slice::SliceExt;
    let mut transpose = vec![Vec::new(); blocksize as usize];
    for block in encoded.chunks(blocksize as usize) {
        for idx in 0u8..blocksize {
            match block.get(idx as usize) {
                Some(l) => transpose[idx as usize].push(*l),
                None    => continue,
            }
        }
    }
    transpose
}

#[test]
fn transpose_test() {
    assert_eq!(transpose(&[1,2,3,4,5,6,7,8], 3),
        vec![vec![1,4,7], vec![2,5,8], vec![3,6]]);
}

fn determine_blocksize(hex: &[u8]) -> u8 {
    use std::slice::SliceExt;
    use std::iter::RandomAccessIterator;
    use std::iter::range_inclusive;
    let mut min_blocksize = 0u8;
    let mut min_dist = 0u32;
    for blocksize in range_inclusive(2u8, 255u8) {
        let mut chunks = hex.chunks(blocksize as usize);
        let chunk0;
        let chunk1;
        match chunks.idx(0) {
            Some(v) => chunk0 = v,
            None    => continue,
        }
        match chunks.idx(1) {
            Some(v) => chunk1 = v,
            None    => continue,
        }
        let dist;
        match hamming::hamming_dist(&chunk0[..], &chunk1[..]) {
            Some(d) => dist=d,
            None    => continue,
        }
        if dist<min_dist || min_blocksize==0u8 {
            min_blocksize = blocksize;
            min_dist = dist;
        }
    }
    if min_blocksize==0u8 {hex.len() as u8}
    else {min_blocksize}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_crack_test() {
        let hex = &super::hex::read_hex(
            "1b37373331363f78151b7f2b783431333d\
             78397828372d363c78373e783a393b3736").unwrap()[..];
        assert_eq!(single_byte_crack(hex), Some(0x58));
}
}
