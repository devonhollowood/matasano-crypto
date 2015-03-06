use std::collections::HashMap;

pub fn best_score(texts: &Vec<String>) -> String {
    let mut min_score = 0f32;
    let mut min_answer = "";
    for text in texts {
        let text_score = score(&text[..]);
        if text_score < min_score || min_score==0f32 {
            min_score = text_score;
            min_answer = &text[..];
        }
    }
    String::from_str(min_answer)
}

pub fn score(text: &str) -> f32 { 
    let n_expected = |c| {english_frequency(c)*(text.len() as f32)};
    let exp : Vec<f32> = KEYS.chars().map(n_expected).collect();
    let occurances = occurances(text);
    let n_observed = |c| {
        *occurances.get(&c).unwrap()
    };
    let obs : Vec<f32> = KEYS.chars().map(n_observed).collect();
    let obs_and_exp : Vec<(f32, f32)> = 
        obs.iter().cloned().zip(exp.iter().cloned()).collect();
    chi_square(obs_and_exp.as_slice())
}

static KEYS : &'static str = "abcdefghijklmnopqrstuvwxyz _"; //_ = "other"

fn to_key(c : char) -> char {
    if KEYS.contains(c.to_lowercase()) {c.to_lowercase()}
    else {'_'}
}

fn occurances(text: &str) -> HashMap<char, f32>{
    let mut counts : HashMap<char, f32> = HashMap::new();
    for c in KEYS.chars() {
        counts.insert(c, 0f32);
    }
    for c in text.chars() {
        match counts.get_mut(&to_key(c)) {
            Some(count) => *count += 1f32,
            None        => continue,
        }
    }
    counts
}

fn chi_square(obs_and_exp : &[(f32, f32)]) -> f32 {
    use std::num::Float;
    let mut sum = 0f32;
    for pair in obs_and_exp {
        let &(obs, exp) : &(f32, f32) = pair;
        sum += (obs-exp).powi(2)/exp;
    }
    sum
}

fn english_frequency(c: char) -> f32{
    match c.to_lowercase() {
        'a' => 0.0609,
        'b' => 0.0105,
        'c' => 0.0284,
        'd' => 0.0292,
        'e' => 0.1136,
        'f' => 0.0179,
        'g' => 0.0138,
        'h' => 0.0341,
        'i' => 0.0544,
        'j' => 0.0024,
        'k' => 0.0041,
        'l' => 0.0292,
        'm' => 0.0276,
        'n' => 0.0544,
        'o' => 0.0600,
        'p' => 0.0195,
        'q' => 0.0024,
        'r' => 0.0495,
        's' => 0.0568,
        't' => 0.0803,
        'u' => 0.0243,
        'v' => 0.0097,
        'w' => 0.0138,
        'x' => 0.0024,
        'y' => 0.0130,
        'z' => 0.0003,
        ' ' => 0.1217,
        _   => 0.0657,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn best_score_test(){
        let a = String::from_str("This is some english text");
        let b = String::from_str("dq;ergjlfkg adg o;iqruiujjkdajg");
        assert_eq!(best_score(&vec![a.clone(), b.clone()]), a);
    }

    #[test]
    fn score_test(){
        let a = "This is some english text";
        let b = "dq;ergjlfkg adg o;iqruiujjkdajg";
        assert!(score(a)<score(b));
    }
}
