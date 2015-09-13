extern crate hyper;
extern crate time;

use hyper::client::Client;
use hyper::header::Connection;
use hyper::status::StatusCode;

const TARGET_HOST: &'static str = "http://localhost:9000";
const TARGET_FILE: &'static str = "test.txt";

fn main() {
    let mut client = Client::new();
    let result = crack(&mut client);
    client.get(TARGET_HOST).header(Connection::close()).send().unwrap();
    match result {
        Some(hmac) => println!("Cracked hmac: {}", format_hex(&hmac[..])),
        None => println!("Could not crack hmac =("),
    }
}

fn crack(mut client: &mut Client) -> Option<[u8; 20]> {
    use std::io::Write;
    let mut query = [0u8; 20];
    for idx in 0..query.len() {
        query[idx] = crack_idx(client, &mut query, idx);
        std::io::stdout().flush().unwrap();
    }
    println!("");
    let target = format!("{}/test?file={}&signature={}",
                         TARGET_HOST, TARGET_FILE, format_hex(&query[..]));
    let response = client.get(&target[..]).send().unwrap();
    match response.status {
        StatusCode::Ok => Some(query),
        StatusCode::InternalServerError => None,
        code => panic!("Unexpected status code: {}", code),
    }
}

fn crack_idx(mut client: &mut Client, query: &mut [u8; 20], idx: usize) -> u8 {
    const NPASSES: usize = 10;
    //get delays
    let mut delays = vec![Vec::new(); 256];
    for pass in 0..(NPASSES as u64) {
        for byte in (0usize..256) {
            query[idx] = byte as u8;
            let new_delay = get_delay(client, &query[..]);
            delays[byte].push(new_delay);
            let complete = idx*NPASSES*256 + (pass as usize)*256 + byte;
            let todo = query.len()*NPASSES*256;
            let percent = complete*100/todo;
            print!("\rCracking ({}%): {}", percent, format_hex(&query[..idx+1]));
        }
    }
    //get best median delay
    let mut max_delay = 0;
    let mut best_byte = 0;
    for byte in 0..delays.len() {
        delays[byte].sort();
        let median = delays[byte][NPASSES/2];
        if median > max_delay {
            max_delay = median;
            best_byte = byte as u8;
        }
    }
    best_byte
}

fn get_delay(client: &mut Client, query: &[u8]) -> u64 {
    let target = format!("{}/test?file={}&signature={}",
                         TARGET_HOST, TARGET_FILE, format_hex(query));
    let start = time::precise_time_ns();
    client.get(&target[..]).send().unwrap();
    let stop = time::precise_time_ns();
    stop - start
}

fn format_hex(hex: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for el in hex.iter() {
        write!(&mut s, "{:02x}", el).unwrap();
    }
    s
}
