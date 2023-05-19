use std::env;
use std::fs;

use sshcerts::ssh::Certificate;

fn help() {
    println!("An SSH Cert Parser based on the sshcerts library");
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

    for (i, line) in contents.split('\n').into_iter().enumerate() {
        if line.is_empty() {
            break;
        }

        let cert = match Certificate::from_string(line) {
            Ok(c) => c,
            Err(e) => {
                println!("Line {}: Certificate not valid: {}", i, e);
                continue;
            }
        };
        println!("{}", cert.key);
    }
}
