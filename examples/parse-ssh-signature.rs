use clap::{Arg, Command};
use std::io;

use sshcerts::{ssh::SshSignature, *};

fn main() {
    let input = io::stdin()
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n")
        .to_string();

    let signature = SshSignature::from_armored_string(&input).unwrap();

    if let Ok(Some(meta)) = signature.metadata() {
        println!("Application:\t\t{}", meta.application().unwrap_or_default());
        println!(
            "User Present:\t\t{}",
            meta.user_presence().unwrap_or_default()
        );
        println!(
            "User Verification:\t{}",
            meta.user_verification().unwrap_or_default()
        );
        println!(
            "Counter:\t\t{}",
            meta.signature_counter().unwrap_or_default()
        );
    } else {
        println!("Couldn't parse metadata.");
    }
}
