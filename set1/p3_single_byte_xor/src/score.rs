mod score{
    use std::collections::VecMap;
    use std::collections::vec_map::Entry;
    pub fn score(text: &String) -> f32 { 
        let mut sum = 0f32;
        for (c, f) in frequencies(text){
            match chi_square(c, f) {
                Some(val) => sum += val;
                None      => continue;
            }
        }
        sum/25
    }
    fn frequencies(text: &str) -> VecMap<char>{
        let mut counts : VecMap<char> = VecMap::new();
        for &c in text {
            match(count.entry(c)){
                Entry::Vacant(v)       => v.insert(1);
                Entry::Occupied(mut v) => {
                    let mv = v.get_mut();
                    *mv += 1;
                }
            }
        }
        counts
    }
    fn chi_square(c: &char, frq :&float) -> Option<float>{
        match english_frequency(c){
            None      => None,
            Some(en_frq) => Some((frq-en_frq).powi(2)/(en_frq)),
        }
    }
    fn english_frequency(c: &char) -> Option<float>{
        if !c.is_alphabetic() {return None;}
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
            'k' => Some(0.00072),
            'j' => Some(0.00153),
            'x' => Some(0.00150),
            'q' => Some(0.00095),
            'z' => Some(0.00074),
        }
    }
}
