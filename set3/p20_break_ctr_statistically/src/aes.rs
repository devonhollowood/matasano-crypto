#![allow(dead_code)]
use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
pub use crypto::symmetriccipher::SymmetricCipherError;

/// This function pads `message` with PKCS7 padding
pub fn pkcs_pad(message: &[u8], blocksize: u8) -> Vec<u8> {
    let padsize = blocksize-(message.len()%(blocksize as usize)) as u8;
    let pad = vec![padsize; padsize as usize];
    message.iter().chain(pad.iter()).cloned().collect()
}

/// This function encrypts `plaintext` using ECB mode AES-128, under `key`.
/// `plaintext` will be PKCS7 padded to a multiple of 128 bits.
pub fn aes_ecb_encrypt(plaintext: &[u8], key: &[u8]) ->
        Result<Vec<u8>, SymmetricCipherError> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength,
        InvalidPadding};
    let mut encryptor = aes::ecb_encryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::NoPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(plaintext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e { //Invalid Padding should never happen
                InvalidLength => return Err(InvalidLength),
                InvalidPadding => panic!("Invalid Padding in aes_ecb_encrypt"),
            },
        }
        final_result.extend(write_buffer.take_read_buffer().take_remaining()
                            .iter().cloned());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

/// This function decrypts `ciphertext` using ECB mode AES, using `key`.
/// `ciphertext`'s length must be a multiple of 128 bits, and the result will
/// be a PKCS7-padded string
pub fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) ->
        Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::NoPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(
            decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)
        );
        final_result.extend(write_buffer.take_read_buffer().take_remaining()
                            .iter().cloned());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

#[cfg(test)]
mod tests {
    use super::pkcs_pad;

    #[test]
    fn simple_pad() {
        let text = "hello world".as_bytes();
        let padded = pkcs_pad(&text, 16u8);
        let expected = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
                        0x6c, 0x64, 0x05, 0x05, 0x05, 0x05, 0x05];
        assert_eq!(padded, expected);
    }

    #[test]
    fn full_pad() {
        let text = "yellow submarine".as_bytes();
        let padded = pkcs_pad(&text, 16u8);
        let expected = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75,
                        0x62, 0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65, 0x10, 0x10,
                        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                        0x10, 0x10, 0x10, 0x10, 0x10];
        assert_eq!(padded, expected);
    }

    use super::aes_ecb_encrypt;

    #[test]
    fn encrypt() {
        let message = "hello world\x05\x05\x05\x05\x05".as_bytes();
        let key = "yellow submarine".as_bytes();
        let output = aes_ecb_encrypt(&message, &key).unwrap();
        let expected = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                        0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5, 0xeb];
        assert_eq!(&output[..], expected);
    }

    use super::aes_ecb_decrypt;

    #[test]
    fn decrypt_success() {
        let ciphertext = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                          0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5, 0xeb];
        let key = "yellow submarine".as_bytes();
        let output = aes_ecb_decrypt(&ciphertext, &key).unwrap();
        let expected = "hello world\x05\x05\x05\x05\x05".as_bytes();
        assert_eq!(&output[..], expected);
    }

    #[test]
    fn decrypt_invalid_length() {
        //ciphertext is only 15 bytes
        let ciphertext = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                          0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5];
        let key = "yellow submarine".as_bytes();
        let output = aes_ecb_decrypt(&ciphertext, &key);
        assert!(output.is_err());
    }
}
