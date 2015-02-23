extern mod hex;
extern mod score;

fn best_score(text : &String) -> Option<(char, String)> {
    let mut min_score = 0f32;
    let default_ans = ('\0', "");
    let mut min_answer = default_ans;
    for c in count<u8>(0, 255){
        let xor = String::from_utf8(repeat(c).take(text.length()));
        let candidate : String; 
        match hex::xor(text, xor){
            Ok(val) => candidate = val;
            Err(_)  => continue;
        }
        let score = score::score(candidate);
        println!("{} had score {}", c, score);
        if (score < min_score || min_score==0) {
            min_score = score;
            min_answer = (c, candidate);
            println!("New minimum!");
        }
    }
    match min_answer {
        default_ans => None;
        other       => Some(other);
    }
}

fn main() {
    let args = std::env::args().skip(1).collect();
    match args.length()i {
        1 => {
            match best_score(args[0]){
                Some((c, s)) => {
                    println!("The best answer was \"{}\" with a score of {}",
                             c, s);
                },
                None => println!("Invalid hex"),
            }
        },
        _ => println!("Invalid number of args!"),
    }
}
