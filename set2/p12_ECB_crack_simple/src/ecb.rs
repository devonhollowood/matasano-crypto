pub fn detect_ecb(ciphertext: &[u8], blocksize: usize) -> bool {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry::{Occupied, Vacant};

    //get blocks
    let blocks = ciphertext.chunks(blocksize);

    //get number of repetitions
    let mut repetitions = HashMap::new();
    for block in blocks {
        match repetitions.entry(block) {
            Vacant(entry)   => {entry.insert(0);},
            Occupied(mut entry) => *entry.get_mut() += 1,
        }
    }
    let mut nrepetitions = 0;
    for value in repetitions.values(){
        nrepetitions += *value;
    }

    nrepetitions > 0
}
