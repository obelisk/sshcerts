use std::env;

use clap::{App, Arg};

use sshcerts::yubikey::fido::Device;

fn main() {
    env_logger::init();
    let matches = App::new("fido-provision")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("A tool to provision a new key on a yubikey")
        .arg(
            Arg::new("pin")
                .about("The pin for the FIDO application on the device.")
                .long("pin")
                .short('p')
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("rpid")
                .about("The remote party identification used for this new key")
                .default_value("sshcerts-fido-rpid")
                .long("rpid")
                .takes_value(true),
        )
        .arg(
            Arg::new("id")
                .about("The ID for this key")
                .default_value("sshcerts-fido-key-id")
                .long("id")
                .takes_value(true),
        )
        .arg(
            Arg::new("name")
                .about("The name of this key")
                .default_value("sshcerts-fido-key-name")
                .long("name")
                .short('n')
                .takes_value(true),
        )
        .arg(
            Arg::new("displayname")
                .about("The display name of this key")
                .default_value("sshcerts-fido-key-displayname")
                .long("displayname")
                .short('d')
                .takes_value(true),
        )

    .get_matches();

    let device = Device::new();

    let registration = device.register(
        matches.value_of("id").unwrap(),
        matches.value_of("name").unwrap(),
        matches.value_of("displayname").unwrap(),
        matches.value_of("rpid").unwrap(),
        matches.value_of("pin"),
    ).unwrap();

    println!("Generated new SSH Public Key [{}]: ", matches.value_of("displayname").unwrap());
    println!("{}", registration.public_key);
    println!("{}", hex::encode(registration.attestation));
}