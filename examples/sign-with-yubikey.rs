use std::env;

use clap::{App, Arg};

use sshcerts::*;
use sshcerts::ssh::SSHCertificateSigner;
use sshcerts::yubikey::piv::{SlotId, Yubikey};

use std::convert::TryFrom;


fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        } 
    } else if slot.len() == 4 && slot.starts_with("0x"){
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Some(SlotId::try_from(slot_value).unwrap())
    } else {
        None
    }
}

fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from("Provided slot was not valid. Should be R1 - R20 or a raw hex identifier")),
    }
}

struct YubikeySigner {
    slot: SlotId,
}

impl SSHCertificateSigner for YubikeySigner {
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>> {
        let mut yk = Yubikey::new().unwrap();
        match yk.ssh_cert_signer(buffer, &self.slot) {
            Ok(sig) => Some(sig),
            Err(_) => None,
        }
    }
}

fn main() {
    env_logger::init();
    let matches = App::new("sign-with-yubikey")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Sign an OpenSSH private key with a Yubikey")
        .arg(
            Arg::new("slot")
                .help("Numerical value for the slot on the yubikey to use for CA")
                .long("slot")
                .short('s')
                .required(true)
                .validator(slot_validator)
                .takes_value(true)
        )
        .arg(
            Arg::new("principal")
                .help("Add this principal to the certificate")
                .long("principal")
                .short('n')
                .takes_value(true)
        )
        .arg(
            Arg::new("key")
                .help("The key to sign with the Yubikey into an SSH certificate")
                .long("key")
                .short('f')
                .required(true)
                .takes_value(true)
        )
        .get_matches();

    let slot = slot_parser(matches.value_of("slot").unwrap()).unwrap();
    let mut yk = Yubikey::new().unwrap();
    let yk_pubkey = yk.ssh_cert_fetch_pubkey(&slot).unwrap();
    let ssh_pubkey = PublicKey::from_path(matches.value_of("key").unwrap()).unwrap();

    let yk_signer = YubikeySigner{slot};


    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &yk_pubkey).unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal(matches.value_of("principal").unwrap())
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_critical_options(CriticalOptions::None)
        .set_extensions(Extensions::Standard)
        .sign(&yk_signer);

    println!("{}", user_cert.unwrap());
}