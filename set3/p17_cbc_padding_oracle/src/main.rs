extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

mod cbc;
mod oracle;

fn crack_block(oracle: &oracle::Oracle, block: &[u8], previous: &[u8]) -> Vec<u8> {
    let mut decrypted = vec![0u8; block.len()]; //fill with ones for xoring
    //crack block one byte at a time, from the end
    let mut idx = 0; //index from end
    let mut start = 0; //starting guess, gets changed on backtrack
    while idx < block.len() {
        let target_idx = block.len()-idx-1;
        //create xor pad
        let mut pad = vec![0u8; block.len()];
        for pad_idx in target_idx..block.len() {
            pad[pad_idx] = idx as u8 + 1;
        }
        let mut first_block = Vec::with_capacity(block.len());
        for fidx in 0..block.len() { //fidx = first block index
            first_block.push(previous[fidx] ^ pad[fidx] ^ decrypted[fidx]);
        }
        //create submission basis
        let mut submission: Vec<u8> =
            first_block.iter().cloned().chain(block.iter().cloned()).collect();
        //loop over possible bytes
        let mut found = false;
        for guess in (start as usize..256).map(|x| x as u8) {
            submission[target_idx] ^= guess; //xor in guessed byte
            if oracle.valid_padding(&submission[..]) {
                decrypted[target_idx] = guess; //update decrypted
                found = true;
                break;
            }
            submission[target_idx] ^= guess; //clean up if not found
        }
        if found { //if you found a good number continue
            idx += 1;
            start = 0;
        }
        else { //otherwise backtrack
            if idx==0 {
                panic!("No solution");
            }
            idx = 0; //go back to the start
            start = decrypted.last().unwrap() + 1; //start where you left off
            decrypted = vec![0; decrypted.len()]; //zero out decrypted
        }
    }
    decrypted
}

fn cbc_padding_attack(oracle: &oracle::Oracle) -> Vec<u8> {
    //encoded using AES-128
    let blocksize = 16;
    //get ciphertext
    let ciphertext = oracle.get();
    //set up result vector
    let mut decrypted = Vec::new();
    //iterate over pairs of blocks
    let first = ciphertext.chunks(blocksize);
    let second = ciphertext.chunks(blocksize).skip(1);
    for (previous, block) in first.zip(second) {
        let decrypted_block = crack_block(oracle, block, previous);
        decrypted.extend(decrypted_block);
    }
    decrypted
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let oracle = oracle::Oracle::new(filename);
    let decrypted = cbc_padding_attack(&oracle);
    let output = match String::from_utf8(decrypted.clone()) {
        Ok(result) => format!("{}", result),
        Err(_) => format!("Error: couldn't convert {:?}", decrypted),
    };
    println!("{}", output);
}
