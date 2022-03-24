use std::env;

use clap::{Command, Arg};

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
            Arg::new("device")
                .help("Manually specify a device to use. If not provided, one will be chosen randomly or by user tap selection (when implemented)")
                .long("device")
                .short('d')
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::new("out")
                .help("Path to write the resultant private key handle to")
                .long("out")
                .short('o')
                .required(false)
                .takes_value(true)
        )
        .get_matches();


    let pin = if let Some(pin) = matches.value_of("pin") {
        Some(pin.to_owned())
    } else {
        None
    };

    let device_path = if let Some(dev) = matches.value_of("device") {
        Some(dev.to_owned())
    } else {
        None
    };

    match generate_new_ssh_key("ssh:test_sk_key", "new-fido-sshkey", pin, device_path) {
        Ok(key) => {
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

        },
        Err(e) => {
            println!("Failed to generate new SSH Key: {}", e.to_string());
        }
    }
}