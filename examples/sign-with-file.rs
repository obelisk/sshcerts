use std::env;

use clap::{App, Arg};

use sshcerts::*;

fn main() {
    env_logger::init();
    let matches = App::new("sign-with-file")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Sign an OpenSSH private key with another OpenSSH private key")
        .arg(
            Arg::new("sign")
                .help("The private key file you want to use as the signing authority")
                .long("signing_key")
                .short('s')
                .required(true)
                .takes_value(true)
        )
        .arg(
            Arg::new("pin")
                .help("If using an SK key handle, what PIN to use with the key (not always needed)")
                .long("pin")
                .short('p')
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::new("principal")
                .help("Add this principal to the certificate")
                .long("principal")
                .short('n')
                .default_value("ubuntu")
                .takes_value(true)
        )
        .arg(
            Arg::new("file")
                .help("The key to sign with the CA into an SSH certificate")
                .long("file")
                .short('f')
                .required(true)
                .takes_value(true)
        )
        .get_matches();


    let ssh_pubkey = PublicKey::from_path(matches.value_of("file").unwrap()).unwrap();
    let mut ca_private_key = PrivateKey::from_path(matches.value_of("sign").unwrap()).unwrap();

    if let Some(pin) = matches.value_of("pin") {
        ca_private_key.set_pin(pin);
    }


    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_private_key.pubkey).unwrap()
        .serial(0x0)
        .key_id("key_id")
        .principal(matches.value_of("principal").unwrap())
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&ca_private_key);

    println!("{}", user_cert.unwrap());
}