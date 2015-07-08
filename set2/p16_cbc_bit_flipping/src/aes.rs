use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
pub use crypto::symmetriccipher::SymmetricCipherError;

/// This function encrypts `plaintext` using CBC mode AES-128, under `key`.
/// `plaintext` will be PKCS7 padded to a multiple of 128 bits.
pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength,
        InvalidPadding};
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(plaintext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e { //These should never happen
                InvalidLength => panic!("Invalid Length in aes_cbc_encrypt"),
                InvalidPadding => panic!("Invalid Padding in aes_cbc_encrypt"),
            },
        }
        final_result.extend(write_buffer.take_read_buffer().take_remaining()
                            .iter().cloned());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    final_result
}

/// This function decrypts `ciphertext` using CBC mode AES, using `key`.
/// `ciphertext`'s length must be a multiple of 128 bits, and the result will
/// be a PKCS7-padded string
pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) ->
        Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);
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
    use super::aes_cbc_encrypt;

    #[test]
    fn encrypt() {
        let message = "hello world".as_bytes();
        let key = "yellow submarine".as_bytes();
        let iv = "the 1st 16 bytes".as_bytes();
        let output = aes_cbc_encrypt(&message, &key, &iv);
        let expected = [224, 191, 66, 17, 60, 77, 69, 210, 210, 160, 37, 129,
                        90, 239, 119, 37];
        assert_eq!(&output[..], expected);
    }

    use super::aes_cbc_decrypt;

    #[test]
    fn decrypt_success() {
        let ciphertext = [224, 191, 66, 17, 60, 77, 69, 210, 210, 160, 37, 129,
                          90, 239, 119, 37];
        let key = "yellow submarine".as_bytes();
        let iv = "the 1st 16 bytes".as_bytes();
        let output = aes_cbc_decrypt(&ciphertext, &key, &iv).unwrap();
        let expected = "hello world".as_bytes();
        assert_eq!(&output[..], expected);
    }

    #[test]
    fn decrypt_invalid_length() {
        //ciphertext is only 15 bytes
        let ciphertext = [0x1c, 0xed, 0xbc, 0x9d, 0x38, 0x91, 0xb7, 0x83, 0x3a,
                          0xdb, 0xf4, 0xcc, 0xf6, 0xc1, 0xf5];
        let key = "yellow submarine".as_bytes();
        let iv = "the 1st 16 bytes".as_bytes();
        let output = aes_cbc_decrypt(&ciphertext, &key, &iv);
        assert!(output.is_err());
    }
}
