extern crate crypto;

#[cfg(test)]
extern crate rand;

mod sha1_mac;

///Given a message `msg` with a SHA1-prefix MAC `msg_sha1`, creates a
///message-and-hash pair. The produced message consists of `msg`, followed by
///padding, followed by `addendum`. The produced hash is the SHA1-prefix MAC
///value for the new message. `verify` is a function to verify that it works.
pub fn forge<F>(msg: &[u8], msg_sha1: &[u8; 20], addendum: &[u8], verify: F)
        -> Option<(Vec<u8>, [u8; 20])> where
        F: Fn(&[u8], &[u8; 20]) -> bool {
    for key_len in 0..1024 {
        //create forged_msg
        let mut forged_msg = Vec::from(msg);
        let pad = create_pad(msg.len() + key_len, 0);
        forged_msg.extend(pad.into_iter());
        forged_msg.extend(addendum.iter().cloned());
        let forged_hash = forge_with_known_key_len(msg, msg_sha1, key_len,
                                                   addendum);
        if verify(&forged_msg, &forged_hash) {
            return Some((forged_msg, forged_hash));
        }
    }
    None
}

///Given a message `msg` with a SHA1-prefix MAC `msg_sha1` and known key length
///`key_len`, creates a message-and-hash pair. The produced message consists of
///`msg`, followed by padding, followed by `addendum`. The produced hash is the
///SHA1-prefix MAC value for the new message.
pub fn forge_with_known_key_len(msg: &[u8], msg_sha1: &[u8; 20], key_len: usize,
                                addendum: &[u8]) -> [u8; 20] {
    let mut sha1_values = combine_to_u32(msg_sha1);
    let len_addition = calculate_padded_len(msg.len() + key_len);
    for chunk in pad_and_partition(len_addition, addendum) {
        sha1_values = sha1_continue(&chunk, &sha1_values);
    }
    split_to_bytes(&sha1_values)
}

#[test]
fn test_forge() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let key_len: usize = rng.gen_range(0, 1024);
    let key: Vec<u8> = rng.gen_iter().take(key_len).collect();
    let mac = sha1_mac::Sha1Mac::new(&key[..]);
    let initial = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                   pound%20of%20bacon";
    let initial_hash = mac.hash(initial);
    let addendum = b";admin=true";
    let (forged, forged_hash) = forge(initial, &initial_hash, addendum,
                                      |msg, hash| mac.validate(msg, hash))
        .expect("Not SHA1 prefix MAC with key len <=1024");
    assert!(mac.validate(&forged, &forged_hash), "Forge yielded incorrect result");
}

#[test]
fn test_forge_with_known_key_len() {
    let mac = sha1_mac::Sha1Mac::new(b"yellow submarine");
    let initial = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                   pound%20of%20bacon";
    let initial_hash = mac.hash(initial);
    assert!(mac.validate(initial, &initial_hash), "initial validation failed");
    let forged = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                  pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                  \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                  \x00\x00\x00\x00\x00\x00\x00\x00\x02\xe8;admin=true";
    let forged_hash = forge_with_known_key_len(&initial[..], &initial_hash, 16,
                                               b";admin=true");
    assert!(mac.validate(forged, &forged_hash), "final validation failed");
}


//TODO: Consider replacing with a generalized [u8]->Vec<u32> function
///Combines an array of 20 u8s to an array of 5 u32s
fn combine_to_u32(bytes: &[u8; 20]) -> [u32; 5] {
    let mut words = [0u32; 5];
    for idx in 0..bytes.len() {
        let shift = (3 - idx % 4)*8; //how much to leftshift by
        words[idx/4] |= (bytes[idx] as u32) << shift;
    }
    words
}

//TODO: Consider replacing with a generalized [u32]->Vec<u8> function
///Splits an array of 5 u32s to an array of 20 u8s
fn split_to_bytes(words: &[u32; 5]) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    for idx in 0..bytes.len() {
        let shift = (3 - idx % 4)*8; //how much to rightshift word by
        bytes[idx] = ((words[idx/4] >> shift) & 0x000000ff) as u8;
    }
    bytes
}

///Gives bytes in `word` in big-endian order
fn u64_bytes_be(word: u64) -> [u8; 8] {
    let mut bytes = [0; 8];
    for idx in 0..bytes.len(){
        bytes[idx] = (word >> (56 - 8 * idx) & 0xff) as u8;
    }
    bytes
}

///Calculates size of a message of `msg_len` length which has been padded for
///SHA1 in bytes. Result is a positive multiple of 64.
fn calculate_padded_len(msg_len: usize) -> usize {
    let old_pad_len = (64 - msg_len % 64) % 64;
    msg_len + old_pad_len
}

///Creates a pad for a message of length `message_len` bytes, adding
///`length_addition` bytes to the total length
fn create_pad(message_len: usize, length_addition: usize) -> Vec<u8> {
    use std::iter::{once, repeat};
    let split_len = u64_bytes_be((message_len + length_addition) as u64 * 8);
    let nzeros = 64 - (message_len + 1 + 8) % 64;
    once(0x80) //leading 0x80
    .chain(repeat(0).take(nzeros)) //zeros
    .chain(split_len.iter().cloned()) //total length
    .collect()
}

///Pads `message` (with `length_addition` bytes added to the total length), and
///partitions the result into a vector of 512-bit chunks
fn pad_and_partition(length_addition: usize, message: &[u8]) -> Vec<[u32; 16]> {
    let pad = create_pad(message.len(), length_addition);
    let padded: Vec<u8> = message.iter().cloned().chain(pad.into_iter()).collect();
    let mut blocks = Vec::new();
    let mut block = [0u32; 16];
    let mut block_idx = 0;
    let mut shift_bytes = 3;
    for byte in padded.iter().cloned() {
        block[block_idx] |= (byte as u32) << shift_bytes * 8;
        if shift_bytes == 0 { // if done with word
            shift_bytes = 3; // reset shift bytes
            block_idx += 1; // go to next word in block
            if block_idx == block.len() { //if done with block
                block_idx = 0;
                blocks.push(block);
                block = [0u32; 16];
            }
        } else {
            shift_bytes -= 1
        };
    }
    blocks
}

///Gives new SHA1 values, given old values `sha1_values` and a block `block`
fn sha1_continue(block: &[u32; 16], sha1_values: &[u32; 5]) -> [u32; 5] {
    let mut w = [0u32; 80];
    //copy block into `w` array
    for idx in 0..block.len() {
        w[idx] = block[idx];
    }
    //extend `w` array with rest of values
    for idx in block.len()..w.len() {
        w[idx] = (w[idx-3] ^ w[idx-8] ^ w[idx-14] ^ w[idx-16]).rotate_left(1);
    }
    //process block
    let mut a = sha1_values[0];
    let mut b = sha1_values[1];
    let mut c = sha1_values[2];
    let mut d = sha1_values[3];
    let mut e = sha1_values[4];
    for idx in 0..80 {
        let f;
        let k;
        if idx < 20 {
            f = (b & c) | (!b & d);
            k = 0x5a827999;
        }
        else if idx < 40 {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        }
        else if idx < 60 {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        }
        else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        let temp = a.rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[idx]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    [sha1_values[0].wrapping_add(a),
     sha1_values[1].wrapping_add(b),
     sha1_values[2].wrapping_add(c),
     sha1_values[3].wrapping_add(d),
     sha1_values[4].wrapping_add(e)]
}

#[cfg(test)]
mod tests {
    #[test]
    fn combine_to_u32() {
        let input = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
                     0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x13, 0x37, 0xc0, 0xde];
        let expected = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0x1337c0de];
        assert_eq!(super::combine_to_u32(&input), expected);
    }

    #[test]
    fn split_to_bytes() {
        let input = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0x1337c0de];
        let expected = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
                        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x13, 0x37, 0xc0, 0xde];
        assert_eq!(super::split_to_bytes(&input), expected);
    }

    #[test]
    fn u64_bytes_be() {
        let expected = [0x13, 0x37, 0xca, 0xfe, 0xc0, 0xde, 0xd0, 0x0d];
        assert_eq!(super::u64_bytes_be(0x1337cafec0ded00d), expected);
    }

    #[test]
    fn calculate_padded_len() {
        assert_eq!(super::calculate_padded_len(0), 0);
        assert_eq!(super::calculate_padded_len(1), 64);
        assert_eq!(super::calculate_padded_len(65), 128);
    }

    #[test]
    fn pad_and_partition_single() {
        let previous = "Charles Dickens";
        let addendum = b"It was the best of times; it was the worst of times";
        let expected = vec![[0x49742077, 0x61732074, 0x68652062, 0x65737420,
                             0x6f662074, 0x696d6573, 0x3b206974, 0x20776173,
                             0x20746865, 0x20776f72, 0x7374206f, 0x66207469,
                             0x6d657380, 0x00000000, 0x00000000, 0x00000398]];
        let len_addition = super::calculate_padded_len(previous.len());
        assert_eq!(super::pad_and_partition(len_addition, &addendum[..]),
                   expected);
    }

    #[test]
    fn pad_and_partition_multiple() {
        let previous = "Charles Dickens";
        let addendum = b"It was the best of times, it was the worst of times, \
                         it was the age of wisdom, it was the age of foolishness";
        let expected = vec![[0x49742077, 0x61732074, 0x68652062, 0x65737420,
                             0x6f662074, 0x696d6573, 0x2c206974, 0x20776173,
                             0x20746865, 0x20776f72, 0x7374206f, 0x66207469,
                             0x6d65732c, 0x20697420, 0x77617320, 0x74686520],
                            [0x61676520, 0x6f662077, 0x6973646f, 0x6d2c2069,
                             0x74207761, 0x73207468, 0x65206167, 0x65206f66,
                             0x20666f6f, 0x6c697368, 0x6e657373, 0x80000000,
                             0x00000000, 0x00000000, 0x00000000, 0x00000560]];
        let len_addition = super::calculate_padded_len(previous.len());
        assert_eq!(super::pad_and_partition(len_addition, &addendum[..]),
                   expected);
    }

    #[test]
    fn sha1_continue() {
        let sha1_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                               0xc3d2e1f0];
        let block = super::pad_and_partition(0, b"yellow submarine")
                    .iter().cloned().next().unwrap();
        let expected = [0xda035e50, 0x1def354e, 0xc3125f4b, 0xb128eb3d, 0xfb2842b7];
        let result = super::sha1_continue(&block, &sha1_values);
        assert_eq!(result, expected);
    }
}
