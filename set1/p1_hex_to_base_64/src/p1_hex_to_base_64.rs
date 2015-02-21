extern crate "rustc-serialize" as serialize;

fn hex_to_base64(s: &String) -> Result<String, serialize::hex::FromHexError> {
    use serialize::hex::{FromHex};
    use serialize::base64::{ToBase64, STANDARD};
    match s.from_hex() {
        Ok(bytes) => Ok(bytes.to_base64(STANDARD)),
        Err(e)    => Err(e),
    }
}

fn main(){
    use std::env;
    for arg in env::args().skip(1) {
        match hex_to_base64(&arg) {
            Ok(res) => println!("{}", res),
            Err(_)  => println!("Invalid hex =("),
        }
    }
}
