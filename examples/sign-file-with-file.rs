use std::env;

use clap::{Arg, Command};

use sshcerts::{ssh::VerifiedSshSignature, *};

fn main() {
    env_logger::init();
    let matches = Command::new("sign-file-with-file")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Sign a file with an OpenSSH private key")
        .arg(
            Arg::new("sign")
                .help("The private key file you want to use to sign the file")
                .long("signing_key")
                .short('s')
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("pin")
                .help("If using an SK key handle, what PIN to use with the key (not always needed)")
                .long("pin")
                .short('p')
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("file")
                .help("The file to sign with the provided key")
                .long("file")
                .short('f')
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let mut private_key = PrivateKey::from_path(matches.value_of("sign").unwrap()).unwrap();

    if let Some(pin) = matches.value_of("pin") {
        private_key.set_pin(pin);
    }

    let contents = std::fs::read(matches.value_of("file").unwrap()).unwrap();

    let signature =
        VerifiedSshSignature::new_with_private_key(&contents, "file", private_key, None).unwrap();

    println!("{}", signature);
}
