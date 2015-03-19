use crypto::{buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) 
        -> Result<Vec<u8>, String> {
    //establish blocksize
    let blocksize = iv.len();
    if blocksize >= 256 {
        return Err(str::to_string("Blocksize too big"));
    }
    if key.len()!=blocksize {
        return Err(str::to_string("Key length does not equal iv length"));
    }

    //pad
    let padded = pkcs_pad(plaintext, blocksize as u8);

    //encrypt
    let mut cipherblocks : Vec<Vec<u8>> 
        = Vec::with_capacity(padded.len()/blocksize);
    for block in padded.chunks(blocksize) {
        let aes_block = {
            let xor_val: &[u8] = match cipherblocks.len() {
                0 => iv,
                l => &cipherblocks[l-1][..],
            };
            let pre_encrypt = xor(block, xor_val).unwrap();
            try!(aes_ecb_encrypt(&pre_encrypt[..], key))
        };
        cipherblocks.push(aes_block);
    }
    let mut ciphertext = Vec::with_capacity(cipherblocks.len()*blocksize);
    for mut block in cipherblocks {
        ciphertext.append(&mut block);
    }
    Ok(ciphertext)
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key:&[u8], iv: &[u8]) 
        -> Result<Vec<u8>, String> {
    //establish blocksize
    let blocksize = iv.len(); 
    if ciphertext.len()%blocksize != 0 || blocksize >= 256 {
        return Err(str::to_string("Invalid blocksize inferred from iv"));
    }
    if key.len()!=blocksize {
        return Err(str::to_string("Key length does not equal iv length"));
    }

    //decrypt
    let mut plainblocks : Vec<Vec<u8>> 
        = Vec::with_capacity(ciphertext.len()/blocksize);
    let mut last_cipherblock = iv;
    for block in ciphertext.chunks(blocksize) {
        let aes_block = try!(aes_ecb_decrypt(block, key));
        let plainblock = xor(&aes_block[..], last_cipherblock).unwrap();
        plainblocks.push(plainblock);
        last_cipherblock = block;
    }
    let mut plaintext = Vec::with_capacity(plainblocks.len()*blocksize);
    for mut block in plainblocks {
        plaintext.append(&mut block);
    }
    Ok(plaintext)
}

fn pkcs_pad(message: &[u8], blocksize: u8) -> Vec<u8> {
    let padsize = blocksize-(message.len()%(blocksize as usize)) as u8;
    let mut result = Vec::with_capacity(message.len() + padsize as usize);
    let mut pad = vec![padsize; padsize as usize];
    result.push_all(message);
    result.append(& mut pad);
    result
}

fn aes_ecb_encrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength, InvalidPadding};
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::NoPadding);
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

fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use crypto::symmetriccipher::SymmetricCipherError::{InvalidLength, InvalidPadding};
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        key,
        blockmodes::NoPadding);
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

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len()!=b.len() {
        return Err(format!("Lengths not equal: {} vs {}", a.len(), b.len()));
    }
    let mut c = Vec::new();
    for (&x, &y) in a.iter().zip(b.iter()){
        c.push(x^y);
    }
    Ok(c)
}
