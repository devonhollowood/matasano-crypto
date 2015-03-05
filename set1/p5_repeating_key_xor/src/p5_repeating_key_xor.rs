mod hex;

fn repeated_key_encrypt(text: &str, key: &str) -> Result<String, String> {
    match hex::repeated_key_xor(text.as_bytes(), key.as_bytes()){
        Ok(u)  => Ok(hex::display_hex(&u[..])),
        Err(e) => Err(format!("{}", e)),
    }
}

fn main() {
    let args : Vec<String> = std::env::args().skip(1).collect();
    match args.len() {
        2 => match repeated_key_encrypt(&args[1][..], &args[0][..]) {
            Ok(s)  => println!("{}", s),
            Err(s) => println!("Error: {}", s),
        },
        _ => println!("Invalid number of args!"),
    }
}
