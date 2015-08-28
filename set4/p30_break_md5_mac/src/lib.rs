#[cfg(test)]
extern crate rand;

#[cfg(test)]
mod md4_mac;

mod md4;
mod bits;

///Given a message `msg` with a MD4-prefix MAC `msg_md4`, creates a
///message-and-hash pair. The produced message consists of `msg`, followed by
///padding, followed by `addendum`. The produced hash is the MD4-prefix MAC
///value for the new message. `verify` is a function to verify that it works.
pub fn forge<F>(msg: &[u8], msg_md4: &[u8; 16], addendum: &[u8], verify: F)
        -> Option<(Vec<u8>, [u8; 16])> where
        F: Fn(&[u8], &[u8; 16]) -> bool {
    for key_len in 0..1024 {
        //create forged_msg
        let mut forged_msg = Vec::from(msg);
        let pad = md4::create_pad(msg.len() + key_len, 0);
        forged_msg.extend(pad.into_iter());
        forged_msg.extend(addendum.iter().cloned());
        let forged_hash = forge_with_known_key_len(msg, msg_md4, key_len,
                                                   addendum);
        if verify(&forged_msg, &forged_hash) {
            return Some((forged_msg, forged_hash));
        }
    }
    None
}

///Given a message `msg` with a MD4-prefix MAC `msg_md4` and known key length
///`key_len`, creates a message-and-hash pair. The produced message consists of
///`msg`, followed by padding, followed by `addendum`. The produced hash is the
///MD4-prefix MAC value for the new message.
pub fn forge_with_known_key_len(msg: &[u8], msg_md4: &[u8; 16], key_len: usize,
                                addendum: &[u8]) -> [u8; 16] {
    let md4_values_vec = bits::u8_to_u32_le(&msg_md4[..]);
    let mut md4_values_iter = md4_values_vec.into_iter();
    let mut md4_values = [0; 4];
    for idx in 0..4 {
        md4_values[idx] = md4_values_iter.next().unwrap();
    }
    let len_addition = md4::calculate_padded_len(msg.len() + key_len);
    for chunk in md4::pad_and_partition(len_addition, addendum) {
        md4_values = md4::md4_continue(&chunk, &md4_values);
    }
    let result_vec = bits::u32_to_u8_le(&md4_values[..]);
    let mut result_iter = result_vec.into_iter();
    let mut result = [0; 16];
    for idx in 0..16 {
        result[idx] = result_iter.next().unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use md4_mac;

    #[test]
    fn test_forge() {
        use super::rand;
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let key_len: usize = rng.gen_range(0, 1024);
        let key: Vec<u8> = rng.gen_iter().take(key_len).collect();
        let mac = md4_mac::Md4Mac::new(&key[..]);
        let initial = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                       pound%20of%20bacon";
        let initial_hash = mac.hash(initial);
        let addendum = b";admin=true";
        let (forged, forged_hash) = super::forge(initial, &initial_hash, addendum,
            |msg, hash| mac.validate(msg, hash))
            .expect("Not MD4 prefix MAC with key len <=1024");
        assert!(mac.validate(&forged, &forged_hash), "Forge yielded incorrect result");
    }

    #[test]
    fn test_forge_with_known_key_len() {
        let mac = md4_mac::Md4Mac::new(b"yellow submarine");
        let initial = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                       pound%20of%20bacon";
        let initial_hash = mac.hash(initial);
        assert!(mac.validate(initial, &initial_hash), "initial validation failed");
        let forged = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20\
                      pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                      \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                      \x00\x00\xe8\x02\x00\x00\x00\x00\x00\x00;admin=true";
        let forged_hash = super::forge_with_known_key_len(
            &initial[..], &initial_hash, 16, b";admin=true");
        assert!(mac.validate(forged, &forged_hash), "final validation failed");
    }
}
