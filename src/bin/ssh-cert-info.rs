use std::env;
use std::fs;

use rustica_sshkey::ssh::Certificate;

fn help() {
    println!("An SSH Cert Parser based on Rustica's sshkey library");
    println!("Usage: ssh-cert-info <path to file>");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        return help();
    }

    let contents = match fs::read_to_string(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            println!("Error {} opening file: {}", e, &args[1]);
            return help();
        }
    };

    let mut i = 0;
    for line in contents.split("\n").into_iter() {
        if line.len() == 0 {
            break
        }
        
        match Certificate::from_string(line) {
            Ok(c) => println!("{:#}", c),
            Err(e) => {
                println!("Line {}: Certificate not valid: {}", i, e);
            }
        };
        i += 1;
    }
}