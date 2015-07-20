use std::collections::HashMap;

/// Returns the best-scoring string contained in `texts`. Scoring is done using
/// the `score()` function.
pub fn best_score(texts: &Vec<String>) -> String {
    let mut min_score = 0f32;
    let mut min_answer = "".to_string();
    // I believe the text to only consist of characters in the range 0x20-0x7e,
    // so each character will be screened to make sure it in in this range
    let valid_char = |c| c >= (0x20 as char) && c <= (0x7e as char);
    for text in texts {
        if text.chars().any(|c| !valid_char(c)) {
            continue;
        }
        let text_score = score(&text[..]);
        if text_score < min_score || min_score==0f32 {
            min_score = text_score;
            min_answer = text.clone();
        }
    }
    min_answer
}

/// Scores `text` for similarity to English, using a chi^2 test. A smaller
/// score is more similar to English.
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
    chi_square(&obs_and_exp[..])
}

/// Chi square test. Given a list of (observed, expected) counts, gives the
/// corresponding chi^2 value
fn chi_square(obs_and_exp : &[(f32, f32)]) -> f32 {
    let mut sum = 0f32;
    for pair in obs_and_exp {
        let &(obs, exp) : &(f32, f32) = pair;
        sum += (obs-exp).powi(2)/exp;
    }
    sum
}

/// Keys used to keep track of number of occurances of a letter in a string
/// '_' corresponds to a non-alphabetic, non space character.
static KEYS : &'static str = "abcdefghijklmnopqrstuvwxyz _";

/// Given some text, gives a map of KEY: (#of occurances of key)
fn occurances(text: &str) -> HashMap<char, f32>{
    let mut counts : HashMap<char, f32> = HashMap::new();
    for c in KEYS.chars() {
        counts.insert(c, 0f32);
    }
    for c in text.chars() {
        *counts.get_mut(&to_key(c)).unwrap() += 1f32;
    }
    counts
}

/// Converts a character to its corresponding representation in KEYS
fn to_key(c : char) -> char {
    if c.to_lowercase().next().is_some() &&
        KEYS.contains(c.to_lowercase().next().unwrap()) {
        c.to_lowercase().next().unwrap()
    }
    else {
        '_'
    }
}

/// Gives the expected english frequency of a character.
fn english_frequency(c: char) -> f32{
    match c.to_lowercase().next() {
        Some('a') => 0.0609,
        Some('b') => 0.0105,
        Some('c') => 0.0284,
        Some('d') => 0.0292,
        Some('e') => 0.1136,
        Some('f') => 0.0179,
        Some('g') => 0.0138,
        Some('h') => 0.0341,
        Some('i') => 0.0544,
        Some('j') => 0.0024,
        Some('k') => 0.0041,
        Some('l') => 0.0292,
        Some('m') => 0.0276,
        Some('n') => 0.0544,
        Some('o') => 0.0600,
        Some('p') => 0.0195,
        Some('q') => 0.0024,
        Some('r') => 0.0495,
        Some('s') => 0.0568,
        Some('t') => 0.0803,
        Some('u') => 0.0243,
        Some('v') => 0.0097,
        Some('w') => 0.0138,
        Some('x') => 0.0024,
        Some('y') => 0.0130,
        Some('z') => 0.0003,
        Some(' ') => 0.1217,
        Some(_)   => 0.0657, //"other" case #1
        None      => 0.0657, //"other" case #2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_score_test(){
        let a = "This is some english text".to_string();
        let b = "dq;ergjlfkg adg o;iqruiujjkdajg".to_string();
        assert_eq!(best_score(&vec![a.clone(), b.clone()]), a);
    }

    #[test]
    fn score_test(){
        let a = "This is some english text";
        let b = "dq;ergjlfkg adg o;iqruiujjkdajg";
        assert!(score(a)<score(b));
    }
}
