use std::env;

use sshcerts::ssh::PublicKey;

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

    match PublicKey::from_path(path) {
        Ok(c) => {
            println!(
                "256 SHA256:{} {}",
                c.fingerprint().hash,
                c.comment.unwrap_or("no comment".to_string())
            );
            Ok(())
        }
        Err(e) => Err(format!("{}: Private key at {} not valid", e, &args[1])),
    }
}
