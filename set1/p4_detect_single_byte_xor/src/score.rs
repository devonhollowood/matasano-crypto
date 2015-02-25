use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub fn best_score(texts: &Vec<String>) -> Option<String> {
    use std::iter::IteratorExt;
    let mut min_score = 0f32;
    let mut min_answer = String::new();
    for text in texts {
        let text_score = score(&text[..]);
        if text_score < min_score || min_score==0f32 {
            min_score = text_score;
            min_answer = text.clone();
        }
    }
    if min_score!=0f32 {println!("Local best: {:?}: {}", min_answer, min_score);}
    if min_score==0f32 {None}
    else {Some(min_answer)}
}

pub fn score(text: &str) -> f32 { 
    let n_alpha = text.chars().filter(|c| {c.is_alphabetic() || *c==' '}).count();
    let n_expected = |c| {english_frequency(c).unwrap()*(n_alpha as f32)};
    let alpha = "abcdefghijklmnopqrstuvwxyz ";
    let exp : Vec<f32> = alpha.chars().map(n_expected).collect();
    let occurances = occurances(text);
    let n_observed = |c| {occurances.get(&c).unwrap().clone()};
    let obs : Vec<f32> = alpha.chars().map(n_observed).collect();
    let obs_and_exp : Vec<(f32, f32)> = 
        obs.iter().cloned().zip(exp.iter().cloned()).collect();
    chi_square(obs_and_exp.as_slice())
}

fn occurances(text: &str) -> HashMap<char, f32>{
    let mut counts : HashMap<char, f32> = HashMap::new();
    for c in "abcdefghijklmnopqrstuvwxyz ".chars() {
        counts.insert(c, 0f32);
    }
    for c in text.chars() {
        match counts.get_mut(&c.to_lowercase()) {
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

fn english_frequency(c: char) -> Option<f32>{
    match c.to_lowercase() {
        'a' => Some(0.0651738),
        'b' => Some(0.0124248),
        'c' => Some(0.0217339),
        'd' => Some(0.0349835),
        'e' => Some(0.1041442),
        'f' => Some(0.0197881),
        'g' => Some(0.0158610),
        'h' => Some(0.0492888),
        'i' => Some(0.0558094),
        'j' => Some(0.0009033),
        'k' => Some(0.0050529),
        'l' => Some(0.0331490),
        'm' => Some(0.0202124),
        'n' => Some(0.0564513),
        'o' => Some(0.0596302),
        'p' => Some(0.0137645),
        'q' => Some(0.0008606),
        'r' => Some(0.0497563),
        's' => Some(0.0515760),
        't' => Some(0.0729357),
        'u' => Some(0.0225134),
        'v' => Some(0.0082903),
        'w' => Some(0.0171272),
        'x' => Some(0.0013692),
        'y' => Some(0.0145984),
        'z' => Some(0.0007836),
        ' ' => Some(0.1918182),
        _   => None,
    }
}
