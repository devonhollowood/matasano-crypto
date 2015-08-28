//!Set of utilities for MD4
mod bits;

pub fn md4(message: &[u8]) -> [u8; 16] {
    let mut md4_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    for block in pad_and_partition(0, message) {
        md4_values = md4_continue(&block, &md4_values);
    }
    let result_vec = bits::u32_to_u8_le(&md4_values[..]);
    let mut result_iter = result_vec.into_iter();
    let mut result = [0; 16];
    for idx in 0..16 {
        result[idx] = result_iter.next().unwrap();
    }
    result
}

///Pads `message` (with `length_addition` bytes added to the total length), and
///partitions the result into a vector of 512-bit chunks
pub fn pad_and_partition(length_addition: usize, message: &[u8]) -> Vec<[u32; 16]> {
    let pad = create_pad(message.len(), length_addition);
    let padded: Vec<u8> = message.iter().cloned().chain(pad.into_iter()).collect();
    let mut blocks = Vec::new();
    let mut block = [0u32; 16];
    let mut block_idx = 0;
    for word in bits::u8_to_u32_le(&padded[..]).into_iter() {
        block[block_idx] = word; //add word
        block_idx += 1; // go to next word in block
        if block_idx == block.len() { //if done with block
            block_idx = 0;
            blocks.push(block);
            block = [0u32; 16];
        }
    }
    blocks
}

///Calculates size of a message of `msg_len` length which has been padded for
///MD4 in bytes. Result is a positive multiple of 64.
pub fn calculate_padded_len(msg_len: usize) -> usize {
    let old_pad_len = (64 - msg_len % 64) % 64;
    msg_len + old_pad_len
}

///Creates a pad for a message of length `message_len` bytes, adding
///`length_addition` bytes to the total length
pub fn create_pad(message_len: usize, length_addition: usize) -> Vec<u8> {
    use std::iter::{once, repeat};
    let split_len = bits::u64_bytes_le((message_len + length_addition) as u64 * 8);
    let nzeros = 64 - (message_len + 1 + 8) % 64;
    once(0x80) //leading 0x80
    .chain(repeat(0).take(nzeros)) //zeros
    .chain(split_len.iter().cloned()) //total length
    .collect()
}

///Gives new MD4 values, given old values `md4_values` and a block `block` to
///digest
pub fn md4_continue(block: &[u32; 16], md4_values: &[u32; 4]) -> [u32; 4] {
    //auxilary functions
    fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
    fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
    fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

    //process block
    let mut a = md4_values[0];
    let mut b = md4_values[1];
    let mut c = md4_values[2];
    let mut d = md4_values[3];

    //round 1
    fn round_1(x:u32, y:u32, z: u32, w: u32, i: u32, s: u32) -> u32 {
        x.wrapping_add(f(y,z,w)).wrapping_add(i).rotate_left(s)
    }
    a = round_1(a, b, c, d, block[ 0],  3);
    d = round_1(d, a, b, c, block[ 1],  7);
    c = round_1(c, d, a, b, block[ 2], 11);
    b = round_1(b, c, d, a, block[ 3], 19);
    a = round_1(a, b, c, d, block[ 4],  3);
    d = round_1(d, a, b, c, block[ 5],  7);
    c = round_1(c, d, a, b, block[ 6], 11);
    b = round_1(b, c, d, a, block[ 7], 19);
    a = round_1(a, b, c, d, block[ 8],  3);
    d = round_1(d, a, b, c, block[ 9],  7);
    c = round_1(c, d, a, b, block[10], 11);
    b = round_1(b, c, d, a, block[11], 19);
    a = round_1(a, b, c, d, block[12],  3);
    d = round_1(d, a, b, c, block[13],  7);
    c = round_1(c, d, a, b, block[14], 11);
    b = round_1(b, c, d, a, block[15], 19);

    //round 2
    fn round_2(x:u32, y:u32, z: u32, w: u32, i: u32, s: u32) -> u32 {
        x.wrapping_add(g(y,z,w)).wrapping_add(i).wrapping_add(0x5a827999)
         .rotate_left(s)
    }
    a = round_2(a, b, c, d, block[ 0],  3);
    d = round_2(d, a, b, c, block[ 4],  5);
    c = round_2(c, d, a, b, block[ 8],  9);
    b = round_2(b, c, d, a, block[12], 13);
    a = round_2(a, b, c, d, block[ 1],  3);
    d = round_2(d, a, b, c, block[ 5],  5);
    c = round_2(c, d, a, b, block[ 9],  9);
    b = round_2(b, c, d, a, block[13], 13);
    a = round_2(a, b, c, d, block[ 2],  3);
    d = round_2(d, a, b, c, block[ 6],  5);
    c = round_2(c, d, a, b, block[10],  9);
    b = round_2(b, c, d, a, block[14], 13);
    a = round_2(a, b, c, d, block[ 3],  3);
    d = round_2(d, a, b, c, block[ 7],  5);
    c = round_2(c, d, a, b, block[11],  9);
    b = round_2(b, c, d, a, block[15], 13);

    //round 3
    fn round_3(x:u32, y:u32, z: u32, w: u32, i: u32, s: u32) -> u32 {
        x.wrapping_add(h(y,z,w)).wrapping_add(i).wrapping_add(0x6ed9eba1)
         .rotate_left(s)
    }
    a = round_3(a, b, c, d, block[ 0],  3);
    d = round_3(d, a, b, c, block[ 8],  9);
    c = round_3(c, d, a, b, block[ 4], 11);
    b = round_3(b, c, d, a, block[12], 15);
    a = round_3(a, b, c, d, block[ 2],  3);
    d = round_3(d, a, b, c, block[10],  9);
    c = round_3(c, d, a, b, block[ 6], 11);
    b = round_3(b, c, d, a, block[14], 15);
    a = round_3(a, b, c, d, block[ 1],  3);
    d = round_3(d, a, b, c, block[ 9],  9);
    c = round_3(c, d, a, b, block[ 5], 11);
    b = round_3(b, c, d, a, block[13], 15);
    a = round_3(a, b, c, d, block[ 3],  3);
    d = round_3(d, a, b, c, block[11],  9);
    c = round_3(c, d, a, b, block[ 7], 11);
    b = round_3(b, c, d, a, block[15], 15);

    //output
    [md4_values[0].wrapping_add(a),
     md4_values[1].wrapping_add(b),
     md4_values[2].wrapping_add(c),
     md4_values[3].wrapping_add(d)]
}

#[cfg(test)]
mod tests {
    use std::fmt::LowerHex;

    pub fn hex_print<I, H>(desc: &str, mut iter: I)
    where H: LowerHex,
          I: Iterator<Item = H> { //debug
        print!("{}: ", desc);
        while let Some(val) = iter.next() {
            print!("{:x} ", val);
        }
        println!("")
    }

    #[test]
    fn md4() {
        let expected = [0xfd, 0x93, 0x87, 0x43, 0x93, 0xff, 0x9f, 0xb2,
                        0x53, 0x77, 0x3a, 0xa3, 0x52, 0x51, 0x06, 0xf5];
        assert_eq!(super::md4(b"yellow submarine"), expected);
    }

    #[test]
    fn calculate_padded_len() {
        assert_eq!(super::calculate_padded_len(0), 0);
        assert_eq!(super::calculate_padded_len(1), 64);
        assert_eq!(super::calculate_padded_len(65), 128);
    }

    #[test]
    fn create_pad_no_addition() {
        use std::iter::{once, repeat};
        let expected = once(0x80)
                       .chain(repeat(0x00).take(39))
                       .chain(super::bits::u64_bytes_le(16*8).iter().cloned())
                       .collect::<Vec<u8>>();
        assert_eq!(super::create_pad(16, 0), expected);
    }

    #[test]
    fn create_pad_with_addition() {
        use std::iter::{once, repeat};
        let expected = once(0x80)
                       .chain(repeat(0x00).take(39))
                       .chain(super::bits::u64_bytes_le(24617*8).iter().cloned())
                       .collect::<Vec<u8>>();
        assert_eq!(super::create_pad(16, 24601), expected);
    }

    #[test]
    fn pad_and_partition_single() {
        let previous = "Charles Dickens";
        let addendum = b"It was the best of times; it was the worst of times";
        let expected = vec![[0x77207449, 0x74207361, 0x62206568, 0x20747365,
                             0x7420666f, 0x73656d69, 0x7469203b, 0x73617720,
                             0x65687420, 0x726f7720, 0x6f207473, 0x69742066,
                             0x8073656d, 0x00000000, 0x00000398, 0x00000000]];
        let len_addition = super::calculate_padded_len(previous.len());
        assert_eq!(super::pad_and_partition(len_addition, &addendum[..]),
                   expected);
    }

    #[test]
    fn pad_and_partition_multiple() {
        let previous = "Charles Dickens";
        let addendum = b"It was the best of times, it was the worst of times, \
                         it was the age of wisdom, it was the age of foolishness";
        let expected = vec![[0x77207449, 0x74207361, 0x62206568, 0x20747365,
                             0x7420666f, 0x73656d69, 0x7469202c, 0x73617720,
                             0x65687420, 0x726f7720, 0x6f207473, 0x69742066,
                             0x2c73656d, 0x20746920, 0x20736177, 0x20656874],
                            [0x20656761, 0x7720666f, 0x6f647369, 0x69202c6d,
                             0x61772074, 0x68742073, 0x67612065, 0x666f2065,
                             0x6f6f6620, 0x6873696c, 0x7373656e, 0x00000080,
                             0x00000000, 0x00000000, 0x00000560, 0x00000000]];
        let len_addition = super::calculate_padded_len(previous.len());
        assert_eq!(super::pad_and_partition(len_addition, &addendum[..]),
                   expected);
    }

    #[test]
    fn md4_continue() {
        let md4_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        let block = super::pad_and_partition(0, b"yellow submarine")
            .into_iter().next().unwrap();
        hex_print("block", block.iter());
        let expected = [0x438793fd, 0xb29fff93, 0xa33a7753, 0xf5065152];
        let result = super::md4_continue(&block, &md4_values);
        println!("");
        hex_print("result  ", result.iter());
        hex_print("expected", expected.iter());
        assert_eq!(result, expected);
    }
}
