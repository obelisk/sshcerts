use std::env;
use std::fs;

use sshcerts::x509::der_encoding_to_ssh_public_key;

fn help() {
    println!("Read a PEM/DER encoded public key and convert it to SSH format");
    println!("Usage: into-ssh-pubkey <path to file>");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        return help();
    }

    let contents = match fs::read(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            println!("Error {} opening file: {}", e, &args[1]);
            return help();
        }
    };

    match der_encoding_to_ssh_public_key(&contents) {
        Ok(public_key) => println!("{}", public_key.to_string()),
        Err(e) => println!("Error: {}", e),
    }
}