use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub fn score(text: &str) -> f32 { 
    let n_alpha = text.chars().filter(|c| {c.is_alphabetic()}).count();
    let n_expected = |c| {english_frequency(c).unwrap()*(n_alpha as f32)};
    let alpha = "abcdefghijklmnopqrstuvwxyz";
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
    for c in "abcdefghijklmnopqrstuvwxyz".chars() {
        counts.insert(c, 0f32);
    }
    for c in text.chars() {
        if !c.is_alphabetic() {continue;}
        *counts.get_mut(&c.to_lowercase()).unwrap() += 1f32;
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
        'e' => Some(0.12702),
        't' => Some(0.09056),
        'a' => Some(0.08167),
        'o' => Some(0.07507),
        'i' => Some(0.06966),
        'n' => Some(0.06749),
        's' => Some(0.06327),
        'h' => Some(0.06094),
        'r' => Some(0.05987),
        'd' => Some(0.04253),
        'l' => Some(0.04025),
        'c' => Some(0.02782),
        'u' => Some(0.02758),
        'm' => Some(0.02406),
        'w' => Some(0.02360),
        'f' => Some(0.02228),
        'g' => Some(0.02015),
        'y' => Some(0.01974),
        'p' => Some(0.01929),
        'b' => Some(0.01492),
        'v' => Some(0.00978),
        'k' => Some(0.00772),
        'j' => Some(0.00153),
        'x' => Some(0.00150),
        'q' => Some(0.00095),
        'z' => Some(0.00074),
        _   => None,
    }
}
