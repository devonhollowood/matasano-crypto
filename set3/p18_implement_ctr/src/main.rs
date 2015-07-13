extern crate crypto;
extern crate rustc_serialize;

mod ctr;
mod aes;

fn main() {
    use rustc_serialize::base64::FromBase64;
    let target = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let ciphertext = target.from_base64().unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    let mut ctr = ctr::AesCtr::new(0, &key[..]);
    let decrypted = ctr.decrypt(&ciphertext[..]).unwrap();
    let s = String::from_utf8(decrypted).unwrap();
    println!("{}", s);
}
