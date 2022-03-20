use std::env;

use clap::{Command, Arg};

use ring::signature::KeyPair;
use sshcerts::*;

use sshcerts::fido::generate::generate_new_ssh_key;

use std::fs::File;

fn main() {
    env_logger::init();
    let matches = Command::new("new-fido-sshkey")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Generate a new SSH Key backed by a hardware token")
        .arg(
            Arg::new("pin")
                .help("If using an SK key handle, what PIN to use with the key (not always needed)")
                .long("pin")
                .short('p')
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::new("out")
                .help("Path to write the resultant private key handle to")
                .long("file")
                .short('f')
                .required(false)
                .takes_value(true)
        )
        .get_matches();


    if let Some(pin) = matches.value_of("pin") {
    //    ca_private_key.set_pin(pin);
    }

    if let Ok(key) = generate_new_ssh_key("test_sk_key", None) {
        println!("{:#}", key.private_key.pubkey);

        if let Some(out) = matches.value_of("out")  {
            let mut out = File::create(out).unwrap();
            key.private_key.write(&mut out).unwrap();
        } else {
            let mut buf = std::io::BufWriter::new(Vec::new());
            key.private_key.write(&mut buf).unwrap();
            let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
            println!("Your new private key handle:\n{}", serialized);
        }

    } else {
        println!("Failed to generate new SSH Key");
    }
}