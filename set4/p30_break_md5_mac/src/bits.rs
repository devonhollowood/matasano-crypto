//!Useful bitwise operations

///Combines a slice of u8s into a Vec of u32s, with the u8s being considered
///to be in big-endian order
pub fn u8_to_u32_be(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::with_capacity(bytes.len()/4); //Vec to store results
    let mut current_word = 0;
    let mut shift = 24; //how much to leftshift each byte by
    for byte in bytes.iter().cloned() {
        current_word |= (byte as u32) << shift; //or in value
        if shift == 0 { //if done with word
            words.push(current_word); //push current_word
            shift = 24; //reset shift
            current_word = 0; //reset current_word
        }
        else {
            shift -= 8; //update shift
        };
    }
    if shift != 24 { //if there is still a word left to push
        words.push(current_word)
    }
    words
}

///Combines a slice of u8s into a Vec of u32s, with the u8s being considered
///to be in little-endian order
pub fn u8_to_u32_le(bytes: &[u8]) -> Vec<u32> {
    let mut words = Vec::with_capacity(bytes.len()/4); //Vec to store results
    let mut current_word = 0;
    let mut shift = 0; //how much to leftshift each byte by
    for byte in bytes.iter().cloned() {
        current_word |= (byte as u32) << shift; //or in value
        if shift == 24 { //if done with word
            words.push(current_word); //push current_word
            shift = 0; //reset shift
            current_word = 0; //reset current_word
        }
        else {
            shift += 8; //update shift
        }
    }
    if shift != 0 { //if there is still a word left to push
        words.push(current_word << (32-shift))
    }
    words
}

///Splits a slice of u32s to a Vec of u8s, in big-endian order
pub fn u32_to_u8_be(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len()*8);
    for word in words.iter() {
        bytes.extend(u32_bytes_be(*word).into_iter());
    }
    bytes
}

///Gives bytes in `word` in big-endian order
pub fn u64_bytes_be(word: u64) -> [u8; 8] {
    let mut bytes = [0; 8];
    for idx in 0..bytes.len(){
        bytes[idx] = (word >> (56 - 8 * idx) & 0xff) as u8;
    }
    bytes
}

///Gives bytes in `word` in little-endian order
pub fn u64_bytes_le(word: u64) -> [u8; 8] {
    let mut bytes = [0; 8];
    for idx in 0..bytes.len(){
        bytes[idx] = (word >> (8 * idx) & 0xff) as u8;
    }
    bytes
}

///Gives bytes in `word` in big-endian order
pub fn u32_bytes_be(word: u32) -> [u8; 4] {
    let mut bytes = [0; 4];
    for idx in 0..bytes.len(){
        bytes[idx] = (word >> (24 - 8 * idx) & 0xff) as u8;
    }
    bytes
}

///Gives bytes in `word` in little-endian order
pub fn u32_bytes_le(word: u32) -> [u8; 4] {
    let mut bytes = [0; 4];
    for idx in 0..bytes.len(){
        bytes[idx] = (word >> (8 * idx) & 0xff) as u8;
    }
    bytes
}

mod tests {
    #[test]
    fn u8_to_u32_be() {
        let input = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
                     0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x13, 0x37, 0xc0, 0xde];
        let expected = vec![0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
                            0x1337c0de];
        assert_eq!(super::u8_to_u32_be(&input[..]), expected);
    }

    #[test]
    fn u8_to_u32_le() {
        let input = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
                     0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x13, 0x37];
        let expected = vec![0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                            0x37130000];
        assert_eq!(super::u8_to_u32_le(&input[..]), expected);
    }

    #[test]
    fn u32_to_u8_be() {
        let input = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0x1337c0de];
        let expected = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe,
                            0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x13, 0x37,
                            0xc0, 0xde];
        assert_eq!(super::u32_to_u8_be(&input[..]), expected);
    }

    #[test]
    fn u64_bytes_be() {
        let expected = [0x13, 0x37, 0xca, 0xfe, 0xc0, 0xde, 0xd0, 0x0d];
        assert_eq!(super::u64_bytes_be(0x1337cafec0ded00d), expected);
    }

    #[test]
    fn u64_bytes_le() {
        let expected_short = [0xde, 0xc0, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(super::u64_bytes_le(0x1337c0de), expected_short);
        let expected_long = [0x0d, 0xd0, 0xde, 0xc0, 0xfe, 0xca, 0x37, 0x13];
        assert_eq!(super::u64_bytes_le(0x1337cafec0ded00d), expected_long);
    }

    #[test]
    fn u32_bytes_be() {
        let expected = [0x13, 0x37, 0xc0, 0xde];
        assert_eq!(super::u32_bytes_be(0x1337c0de), expected);
    }

    #[test]
    fn u32_bytes_le() {
        let expected = [0xde, 0xc0, 0x37, 0x13];
        assert_eq!(super::u32_bytes_le(0x1337c0de), expected);
    }

}
