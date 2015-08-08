extern crate crypto;
extern crate rand;

mod cbc;
mod oracle;

//retrieves key for AES-128 CBC when key = IV
fn crack_key(oracle : &oracle::Oracle) -> Vec<u8> {
    //make the plain text five blocks long to preserve padding
    let plaintext = std::iter::repeat('A').take(5*16).collect::<String>();
    let ciphertext = oracle.encrypt(&plaintext[..]);
    let block1 = ciphertext.chunks(16).next().unwrap();
    let substitute = block1.iter().cloned()
                           .chain(std::iter::repeat(0u8).take(16))
                           .chain(block1.iter().cloned())
                           .chain(ciphertext.iter().cloned().skip(3*16))
                           .collect::<Vec<u8>>();
    let sub_plain = match oracle.decrypt(&substitute[..]) {
        Err(oracle::DecryptError::BadAscii(v)) => v,
        Ok(s) => s.into_bytes(),
        _ => panic!("Bad decryption"),
    };
    let mut sub_blocks = sub_plain.chunks(16);
    sub_blocks.next().unwrap().iter().zip(
                   sub_blocks.skip(1).next().unwrap().iter()
               ).map(|(a,b)| a ^ b).collect::<Vec<u8>>()
}

#[test]
fn it_works() {
    let oracle = oracle::Oracle::new();
    let message = "Attack at dawn";
    let ciphertext = oracle.encrypt(&message);
    let key = crack_key(&oracle);
    let decoded = cbc::aes_cbc_decrypt(&ciphertext[..], &key[..], &key[..])
                  .unwrap();
    assert_eq!(message.as_bytes(), &decoded[..])
}
