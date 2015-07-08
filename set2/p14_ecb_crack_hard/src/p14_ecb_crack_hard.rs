#![allow(dead_code)]
extern crate rustc_serialize as serialize;
extern crate crypto;
extern crate rand;

mod aes;
mod ecb;
mod oracle;
use oracle::AesEcbOracle;

fn find_blocksize(oracle: &AesEcbOracle) -> usize {
    //establish baseline for first changing block
    let oracle0 = oracle.encrypt(&[]);
    let oracle1 = oracle.encrypt(&[0]);
    let mut previous_diff = first_difference(oracle0.iter(), oracle1.iter());
    //find next block that changes. blocksize is difference between blocks
    for n in 2..65 { //65 = 2*(max AES block size) + 1
        let previous_pad = vec![0; n-1];
        let pad = vec![0; n];
        let previous = oracle.encrypt(&previous_pad[..]);
        let current = oracle.encrypt(&pad[..]);
        let diff = first_difference(previous.iter(), current.iter());
        if diff != previous_diff {
            //here dc is short for "double check"
            let dc_previous_pad = vec![1; n-1];
            let dc_pad = vec![1; n];
            let dc_previous = oracle.encrypt(&dc_previous_pad[..]);
            let dc = oracle.encrypt(&dc_pad[..]);
            let dc_diff = first_difference(dc_previous.iter(), dc.iter());
            if dc_diff == diff {
                return diff-previous_diff;
            }
        }
        previous_diff = diff;
    }
    panic!("Invalid blocksize");
}

#[test]
fn find_blocksize_test() {
    let oracle = AesEcbOracle::new("hello world".as_bytes());
    assert_eq!(find_blocksize(&oracle), 16);
}

#[test]
fn find_blocksize_prefix_multiple_of_blocksize() {
    let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
               0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
    let prefix = vec![0x41, 16];
    let oracle = AesEcbOracle::controlled(&key, "hello world".as_bytes(), &prefix[..]);
    assert_eq!(find_blocksize(&oracle), 16);
}

fn find_prefix_size(oracle: &AesEcbOracle, blocksize: usize) -> usize {
    //establish baseline for first changing block
    let oracle0 = oracle.encrypt(&[]);
    let oracle1 = oracle.encrypt(&[0]);
    let baseline_diff = first_difference(oracle0.chunks(blocksize),
                                         oracle1.chunks(blocksize));
    for pad_size in 1..blocksize+1 {
        //set up blocks
        let pad = vec![0; pad_size];
        let encrypted = oracle.encrypt(&pad[..]);
        let blocks = encrypted.chunks(blocksize);
        //set up next_blocks
        let next_pad = vec![0; pad_size+1];
        let next_encrypted = oracle.encrypt(&next_pad[..]);
        let next_blocks = next_encrypted.chunks(blocksize);
        //get diff
        let diff = first_difference(blocks, next_blocks);
        if diff != baseline_diff {
            //here dc is short for "double check"
            let dc_pad = vec![1; pad_size];
            let dc = oracle.encrypt(&dc_pad[..]);
            let dc_next_pad = vec![1; pad_size];
            let dc_next = oracle.encrypt(&dc_next_pad[..]);
            let dc_diff = first_difference(dc.chunks(blocksize),
                                           dc_next.chunks(blocksize));
            if dc_diff != baseline_diff {
                let prefix_size = (diff-1)*blocksize+(blocksize-pad_size);
                return prefix_size;
            }
        }
    }
    panic!("Invalid prefix size!");
}

#[test]
fn find_prefix_size_0() {
    let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
               0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
    let oracle = AesEcbOracle::controlled(&key, "hello world".as_bytes(), &[]);
    assert_eq!(find_prefix_size(&oracle, 16), 0);
}

#[test]
fn find_prefix_size_1() {
    let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
               0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
    let prefix = vec![0; 1];
    let oracle = AesEcbOracle::controlled(&key, "hello world".as_bytes(), &prefix[..]);
    assert_eq!(find_prefix_size(&oracle, 16), 1);
}

#[test]
fn find_prefix_size_255() {
    let key = [0x79, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x73, 0x75, 0x62,
               0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65]; //"yellow submarine"
    let prefix = vec![0; 255];
    let oracle = AesEcbOracle::controlled(&key, "hello world".as_bytes(), &prefix[..]);
    assert_eq!(find_prefix_size(&oracle, 16), 255);
}

fn first_difference<T, I, J>(mut a: I, mut b: J) -> usize
    where T: PartialEq,
          I: Iterator<Item=T>,
          J: Iterator<Item=T> {
    let mut diff_n = 0usize;
    while let (Some(x), Some(y)) = (a.next(), b.next()) {
        if x == y {
            diff_n += 1;
        }
        else {
            break;
        }
    }
    diff_n
}

#[test]
fn first_difference_diff() {
    let a = "012345".to_string();
    let b = vec!['0','1','2','4','5'];
    assert_eq!(first_difference(a.chars(), b.iter().cloned()), 3);
}

#[test]
fn first_difference_same() {
    let a = "012345".to_string();
    let b = vec!['0','1','2','3','4','5'];
    assert_eq!(first_difference(a.chars(), b.iter().cloned()), 6);
}

fn crack_block(oracle: &AesEcbOracle, blocksize: usize, prefix_size: usize,
               so_far : &[u8]) -> Vec<u8> {
    let target_idx = (prefix_size + so_far.len())/blocksize + 1; //index of targeted block
    let prefix_pad_size = blocksize - (prefix_size % blocksize);
    let mut solved = Vec::new();
    while solved.len() < blocksize {
        let pad = vec![0; prefix_pad_size + blocksize-solved.len()-1];
        let pad_encrypted = oracle.encrypt(&pad[..]);
        let target_block = pad_encrypted.chunks(blocksize).nth(target_idx)
                                        .unwrap();
        let mut test = pad.iter().cloned().chain(
            so_far.iter().cloned()
        ).chain(
            solved.iter().cloned()
        ).collect::<Vec<u8>>();
        let mut found=false;
        for byte in (0..256).map(|x| x as u8) {
            test.push(byte); //add test byte
            let encrypted = oracle.encrypt(&test[..]);
            let test_block = encrypted.chunks(blocksize)
                                      .nth(target_idx).unwrap();
            test.pop(); //clean up
            if test_block == target_block {
                found = true;
                solved.push(byte);
                break;
            }
        }
        if !found {
            // If this approach suddenly fails, you've hit the pad at the end of
            // the message, which shifts each time you change the pad length.
            // This gives a "moving target" for the last few bytes. It'll fail
            // after appending a 0x01, and the pad changes to 0x02 0x02. Thus
            // you can "fix" the issue by just popping the 0x01 byte and
            // re-padding.
            solved.pop();
            return aes::pkcs_pad(&solved[..], blocksize as u8);
        }
    }
    solved
}

fn crack_ecb_oracle(oracle: &AesEcbOracle)
        -> Result<Vec<u8>, String> {
    let blocksize = find_blocksize(oracle);
    let prefix_size = find_prefix_size(oracle, blocksize);
    let ciphertext = oracle.encrypt(&[]);
    let ecb_test = vec![0x41; 3*blocksize].into_iter().chain(
        ciphertext.iter().cloned()
    ).collect::<Vec<u8>>();
    if !ecb::detect_ecb(&ecb_test[..], blocksize) {
        return Err("Wasn't ecb".to_string());
    }
    let mut so_far = Vec::<u8>::new();
    while so_far.len() + prefix_size < ciphertext.len() {
        let next = crack_block(oracle, blocksize, prefix_size, &so_far[..]);
        so_far.extend(next);
    }
    Ok(so_far)
}

fn read_base64_file(filename: &str) -> Result<Vec<u8>,String> {
    use std::io::prelude::*;
    use std::fs::File;
    use self::serialize::base64::FromBase64;
    let mut f;
    match File::open(filename) {
        Ok(file) => f=file,
        Err(e)   => {
            return Err(format!("Couldn't open {}: {}", filename, e));
        }
    }
    let mut contents_b64 = String::new();
    match f.read_to_string(&mut contents_b64) {
        Ok(_) => {},
        Err(e) => {
            return Err(format!("Couldn't read {}: {}", filename, e));
        }
    }
    let contents_joined: String =
        contents_b64[..].chars().filter(|c| *c!='\n').collect();
    match contents_joined[..].from_base64() {
        Ok(vec) => Ok(vec),
        Err(e)  => Err(format!("Couldn't parse base 64: {}", e)),
    }
}

fn main() {
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let contents;
    match read_base64_file(filename) {
        Ok(c)  => contents = c,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }
    let oracle = AesEcbOracle::new(&contents[..]);
    let output;
    match crack_ecb_oracle(&oracle){
        Ok(v)  => match String::from_utf8(v) {
                      Ok(result) => output = format!("{}", result),
                      Err(e) => output = format!("{}", e),
                  },
        Err(e) => output = format!("Error: {}", e),
    }
    println!("{}", output)
}
