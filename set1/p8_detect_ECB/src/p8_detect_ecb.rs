#![feature(rustc_private)]
#![feature(core)]
#![feature(io)]
#![feature(std_misc)]

extern crate serialize;

fn detect_ecb(ciphertext: &[u8], blocksize: u16) -> bool {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry::{Occupied, Vacant};
    use std::num::Int;
    use std::slice::SliceExt;

    //get blocks
    let blocks = ciphertext.chunks(blocksize as usize);
    let nblocks = blocks.len();
    
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
    
    //calculate probablility
    let expected = 
        (nblocks.pow(2) as f32)/(2.pow(blocksize as u32) as f32);
    
    nrepetitions as f32 > expected
}

fn read_hex_lines(filename: &str) -> Result<Vec<Vec<u8>>,String> {
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::fs::File;
    use serialize::hex::FromHex;

    let mut buffer;
    match File::open(filename) {
        Ok(file) => buffer=BufReader::new(file),
        Err(e)   => {
            return Err(format!("Couldn't open {}: {}", filename, e));
        }
    }
    
    let hex_lines = buffer.lines();
    let mut lines = Vec::new();
    for line_res in hex_lines {
        let line;
        match line_res {
            Ok(s)  => line = s,
            Err(e) => {
                return Err(format!("Couldn't read {}: {}", filename, e));
            }
        }
        match line[..].from_hex() {
            Ok(v) => lines.push(v),
            Err(e) => {
                return Err(format!("Couldn't parse {}: {}", line, e));
            }
        }
    }
    Ok(lines)
}

fn main() {
    use std::iter::IteratorExt;
    use serialize::hex::ToHex;

    let args : Vec<String> = std::env::args().collect();
    if args.len()!=2 {
        println!("Invalid number of args!");
        return;
    }
    let filename = &args[1][..];
    let lines;
    match read_hex_lines(filename) {
        Ok(ls)  => lines = ls,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    }

    for (line_num, line) in lines.into_iter().enumerate(){
        if detect_ecb(&line[..], 16){
            println!("{}: {}", line_num, line.to_hex());
        }
    }
}
