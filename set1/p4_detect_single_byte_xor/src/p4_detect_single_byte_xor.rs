mod hex;
mod score;

fn detect_single_byte_xor(filename : &str) -> Result<String, String> {
    let lines : Vec<String>;
    match file_lines(filename) {
        Some(ls) => lines = ls,
        None     => return Err("could not read file".to_string()),
    }
    let mut best_guesses = Vec::new();
    for line in lines {
        match single_byte_xor_crack(&line[..]) {
            Some(s) => {
                best_guesses.push(s);
            },
            None    => continue,
        }
    }
    match score::best_score(&best_guesses) {
        Some(s) => Ok(s),
        None    => Err("no valid lines in file".to_string())
    }
}

fn single_byte_xor_crack(text_hex: &str) -> Option<String> {
    let mut decryptions = Vec::new();
    for byte in std::iter::count(0u8, 1u8).take(256){
        match hex::single_byte_xor(text_hex, byte){
            Ok(res) => {
                match hex::hex_to_ascii(&res[..]) {
                    Ok(ascii) => decryptions.push(ascii),
                    Err(e)    => {
                        continue;
                    }
                }
            }
            Err(_)  => {
                continue;
            }
        }
    }
    score::best_score(&decryptions)
}

fn file_lines(filename : &str) -> Option<Vec<String>> {
    use std::fs::File;
    use std::io::BufReadExt;
    let mut f : File;
    match File::open(filename){
        Ok(file) => f = file,
        Err(_)   => return None,
    }
    let mut result = Vec::new();
    for line in std::io::BufReader::new(f).lines() {
        match line {
            Ok(l)  => result.push(l.clone()),
            Err(_) => continue,
        }
    }
    Some(result)
}

fn main() {
    let args : Vec<String> = std::env::args().skip(1).collect();
    match args.len() {
        1 => match detect_single_byte_xor(&args[0][..]) {
            Ok(s)  => println!("{}", s),
            Err(e) => println!("Error: {}", e),
            },
        _ => println!("Error: invalid number of args!"),
    }
}
