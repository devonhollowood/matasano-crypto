mod bits;

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
    //shifts for each round
    let s: [u32; 64] = [ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12,
                        17, 22,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                         5,  9, 14, 20,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11,
                        16, 23,  4, 11, 16, 23,  6, 10, 15, 21,  6, 10, 15, 21,
                         6, 10, 15, 21,  6, 10, 15, 21];

    //"k" array
    let k: [u32; 64] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

    //process block
    let mut a = md4_values[0];
    let mut b = md4_values[1];
    let mut c = md4_values[2];
    let mut d = md4_values[3];
    for idx in 0..63 {
        let f;
        let g;
        if idx < 16 {
            f = (b & c) | (!b & d);
            g = idx;
        }
        else if idx < 32 {
            f = (d & b) | (!d & c);
            g = (5*idx + 1) % 16;
        }
        else if idx < 48 {
            f = b ^ c ^ d;
            g = (3*idx + 5) % 16;
        }
        else {
            f = c ^ (b | !d);
            g = (7*idx) % 16;
        }
        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
                (a.wrapping_add(f)
                  .wrapping_add(k[idx])
                  .wrapping_add(block[g])
                ).rotate_left(s[idx])
            );
        a = temp;
    }

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
            .into_iter().next().unwrap(); //TODO: fix
        //let block = [0x6c6c6579, 0x7320776f, 0x616d6275, 0x656e6972, 0x00000080, 0x0,
        //             0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80000000, 0x0];
        hex_print("block", block.iter());
        let expected = [0x17c25ea3, 0xd21d5ce1, 0x181a2058, 0x7c891448];
        let result = super::md4_continue(&block, &md4_values);
        println!("");
        hex_print("result  ", result.iter());
        hex_print("expected", expected.iter());
        assert_eq!(result, expected);
    }
}
