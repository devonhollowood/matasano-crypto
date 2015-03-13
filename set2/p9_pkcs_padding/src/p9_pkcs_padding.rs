#![feature(collections)]

fn pkcs_pad(message: &[u8], blocksize: u8) -> Vec<u8> {
    let padsize = blocksize-(message.len()%(blocksize as usize)) as u8;
    let mut result = Vec::with_capacity(message.len() + padsize as usize);
    let mut pad = vec![padsize; padsize as usize];
    result.push_all(message);
    result.append(& mut pad);
    result
}

fn main(){
    use std::str::FromStr;
    let args : Vec<String> = std::env::args().collect();
    if args.len()!=3 {
        println!("Invalid number of args!");
        return;
    }
    let message = &args[1][..];
    let blocksize;
    match u8::from_str(&args[2][..]){
        Ok(n)  => blocksize = n,
        Err(e) => {
            println!("Could not parse u8 from padsize: {}", e);
            return;
        }
    }
    
    let padded_message = pkcs_pad(message.as_bytes(), blocksize);

    println!("{:?}", padded_message);
    match String::from_utf8(padded_message) {
        Ok(s) => println!("({:?})", s),
        Err(_) => {},
    }
}
