extern crate crypto;
extern crate hyper;
extern crate rustc_serialize;
extern crate rand;

mod hmac_sha1;

use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;

const HOST: &'static str = "localhost:9000";
const DELAY: u32 = 1;

fn main() {
    let key = gen_key();
    println!("Key: {} (len {})", format_hex(&key[..]), key.len());
    let server = Server::http(HOST).unwrap();
    println!("test.txt hmac: {} (Shhhh!)",
             format_hex(&file_hmac(&key[..], "test.txt").unwrap()[..]));
    println!("Listening on port 9000");
    server.handle(
        move |req: Request, res: Response| {
            handle_request(&key[..], req, res)
        }
    ).unwrap();
}

fn format_hex(hex: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for el in hex.iter() {
        write!(&mut s, "{:02x}", el).unwrap();
    }
    s
}

fn gen_key() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let key_len = rng.gen_range(10, 256);
    rng.gen_iter().take(key_len).collect()
}

fn handle_request(key: &[u8], req: Request, mut res: Response<Fresh>) {
    match req.method {
        hyper::Get => {
            match req.uri {
                AbsolutePath(path) => *res.status_mut() = handle_path(key, &path[..]),
                _ => *res.status_mut() = StatusCode::NotFound,
            }
        },
        _ => *res.status_mut() = StatusCode::MethodNotAllowed,
    }
    send_response(res);
}

fn handle_path(key: &[u8], path: &str) -> StatusCode {
    let full_path = format!("http://{}/{}", HOST, path);
    match hyper::Url::parse(&full_path[..]).ok().and_then(|url| url.query_pairs()) {
        Some(pairs) => {
            if pairs.len() == 2 {
                let (ref arg1, ref filename) = pairs[0];
                let (ref arg2, ref signature) = pairs[1];
                if &arg1[..]=="file" && &arg2[..]=="signature" {
                        check_signature(key, &filename[..], &signature[..])
                    }
                else { StatusCode::BadRequest }
            }
            else { StatusCode::BadRequest }
        },
        _ => StatusCode::NotFound,
    }
}

fn send_response(res: Response) {
    match res.status() {
        StatusCode::Ok =>
            { res.send(b"<h1>Server says everything is a-okay</h1>\n").unwrap(); },
        StatusCode::BadRequest =>
            { res.send(b"<h1>400: Bad Request</h1>\n").unwrap(); },
        StatusCode::NotFound =>
            { res.send(b"<h1>404: Not Found</h1>\n").unwrap(); },
        StatusCode::MethodNotAllowed =>
            { res.send(b"<h1>405: Method Not Allowed</h1>\n").unwrap(); },
        StatusCode::InternalServerError =>
            { res.send(b"<h1>500: Internal Server Error</h1>\n").unwrap(); },
        _ => {},
    }
}

fn check_signature(key: &[u8], filename: &str, signature: &str) -> StatusCode {
    use rustc_serialize::hex::FromHex;
    let parsed_signature = match signature.from_hex() {
        Ok(sig) => sig,
        _ => return StatusCode::BadRequest,
    };
    let file_hash = match file_hmac(key, filename) {
        Ok(sha1) => sha1,
        _ => return StatusCode::NotFound,
    };
    if insecure_compare(&file_hash[..], &parsed_signature[..]) {
        StatusCode::Ok
    }
    else {
        StatusCode::InternalServerError
    }
}

fn file_hmac(key: &[u8], filename: &str) -> std::io::Result<[u8; 20]> {
    use std::io::prelude::*;
    use std::fs::File;
    let mut file = try!(File::open(filename));
    let mut s = String::new();
    try!(file.read_to_string(&mut s));
    Ok(hmac_sha1::hmac_sha1(key, &s.into_bytes()[..]))
}

fn insecure_compare(first: &[u8], second: &[u8]) -> bool {
    for (x, y) in first.iter().zip(second.iter()) {
        if { x != y } { return false; }
        std::thread::sleep_ms(DELAY);
    }
    if first.len() != second.len() { //do this after step-by-step to preserve
        return false;                //element-by-element comparison
    }
    true
}

#[cfg(test)]
mod tests {

    #[test] #[ignore]
    fn insecure_compare() {
        assert!(super::insecure_compare(b"yellow submarine", b"yellow submarine"),
            "should have been equal");
        assert!(!super::insecure_compare(b"yellow submarine", b"yellow_submarine"),
            "should have been unequal");
    }

}
