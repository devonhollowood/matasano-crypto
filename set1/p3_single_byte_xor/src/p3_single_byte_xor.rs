extern crate "rustc-serialize" as serialize;
mod hex;
mod score;

fn best_score(text : &str) -> Option<(u8, String)> {
    use hex;
    use score;
    let mut min_score = 0f32;
    let default_ans = (0u8, String::new());
    let mut min_answer = default_ans.clone();
    for c in std::iter::count(0u8, 1u8).take(255){
        use self::serialize::hex::{FromHex, ToHex};
        use std::iter::repeat;
        let xor : Vec<u8> = repeat(c).take(text.len()/2).collect();
        let candidate_hex : String; 
        match hex::xor(text, xor.as_slice().to_hex().as_slice()){
            Ok(val) => candidate_hex = val,
            Err(E)  => {
                println!("{}: {}", c, E);
                continue
            },
        }
        let candidate : String;
        match String::from_utf8(candidate_hex.from_hex().unwrap()) {
            Ok(s)  => candidate = s,
            Err(_) => continue,
        }
        let score = score::score(candidate.as_slice());
        println!("0x{:x}: had score {}", c, score);
        if (score < min_score || min_score==0f32) {
            min_score = score;
            min_answer = (c, candidate);
            println!("New minimum!");
        }
    }
    if min_answer==default_ans {None}
    else {Some(min_answer)}
}

fn main() {
    let args : Vec<String> = std::env::args().skip(1).collect();
    match args.len() {
        1 => {
            match best_score(args[0].as_slice()){
                Some((c, s)) => {
                    println!("The best answer was \"0x{:x}\", \
                             which decoded to \"{}\"",
                             c, s);
                },
                None => println!("Invalid hex"),
            }
        },
        _ => println!("Invalid number of args!"),
    }
}
