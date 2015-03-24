use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub fn pkcs_pad(message: &[u8], blocksize: u8) -> Vec<u8> {
    let padsize = blocksize-(message.len()%(blocksize as usize)) as u8;
    let mut result = Vec::with_capacity(message.len() + padsize as usize);
    let mut pad = vec![padsize; padsize as usize];
    result.push_all(message);
    result.append(& mut pad);
    result
}

pub fn aes_ecb_encrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength,
        InvalidPadding};
    let mut encryptor = aes::ecb_encryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e {
                InvalidLength => return Err(str::to_string("Invalid Length")),
                InvalidPadding => return Err(str::to_string("Invalid Padding")),
            },
        }
        final_result.push_all(
            write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

pub fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength, 
        InvalidPadding};
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e {
                InvalidLength => return Err(str::to_string("Invalid Length")),
                InvalidPadding => return Err(str::to_string("Invalid Padding")),
            },
        }
        final_result.push_all(
            write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

pub fn aes_cbc_encrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) 
        -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength,
        InvalidPadding};
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result;
        match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e {
                InvalidLength => return Err(str::to_string("Invalid Length")),
                InvalidPadding => return Err(str::to_string("Invalid Padding")),
            },
        }
        final_result.push_all(
            write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) 
        -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength,
        InvalidPadding};
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
        let result;
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r)  => result = r,
            Err(e) => match e {
                InvalidLength => return Err(str::to_string("Invalid Length")),
                InvalidPadding => return Err(str::to_string("Invalid Padding")),
            },
        }
        final_result.push_all(
            write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}
