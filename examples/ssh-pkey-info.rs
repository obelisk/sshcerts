use std::env;

use sshcerts::ssh::PrivateKey;

fn help() {
    println!("An SSH Private Key reader based on the sshcerts library");
    println!("Usage: ssh-pkey-info <path to file>");
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        help();
        return Ok(());
    }

    let path = &args[1];

    let passphrase = if args.len() == 3 {
        Some(args[2].clone())
    } else {
        None
    };

    match PrivateKey::from_path_with_passphrase(path, passphrase) {
        Ok(c) => {
            println!("{:#}", c);
            Ok(())
        }
        Err(e) => Err(format!("{}: Private key at {} not valid", e, &args[1])),
    }
}
