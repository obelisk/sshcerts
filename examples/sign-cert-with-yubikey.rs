use std::env;

use clap::{Arg, Command};

use sshcerts::ssh::SSHCertificateSigner;
use sshcerts::yubikey::piv::{SlotId, Yubikey};
use sshcerts::*;

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
    } else if slot.len() == 4 && slot.starts_with("0x") {
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Some(SlotId::try_from(slot_value).unwrap())
    } else {
        None
    }
}

fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from(
            "Provided slot was not valid. Should be R1 - R20 or a raw hex identifier",
        )),
    }
}

struct YubikeySigner {
    slot: SlotId,
    pin: String,
    mgm_key: Vec<u8>,
}

impl SSHCertificateSigner for YubikeySigner {
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>> {
        let mut yk = Yubikey::new().unwrap();
        yk.unlock(self.pin.as_bytes(), &self.mgm_key).unwrap();
        println!("Unlocking Successful");

        match yk.ssh_cert_signer(buffer, &self.slot) {
            Ok(sig) => Some(sig),
            Err(e) => {
                println!("Error signing: {:?}", e);
                None
            }
        }
    }
}

fn main() {
    env_logger::init();
    let matches = Command::new("sign-cert-with-yubikey")
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
                .takes_value(true),
        )
        .arg(
            Arg::new("principal")
                .help("Add this principal to the certificate")
                .long("principal")
                .short('n')
                .default_value("ubuntu")
                .takes_value(true),
        )
        .arg(
            Arg::new("key")
                .help("The key to sign with the Yubikey into an SSH certificate")
                .long("key")
                .short('f')
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("pin")
                .help("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .default_value("123456")
                .long("pin")
                .short('p')
                .takes_value(true),
        )
        .arg(
            Arg::new("management-key")
                .help("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .default_value("010203040506070801020304050607080102030405060708")
                .long("mgmkey")
                .short('m')
                .takes_value(true),
        )
        .get_matches();

    let slot = slot_parser(matches.value_of("slot").unwrap()).unwrap();
    let mut yk = Yubikey::new().unwrap();

    let yk_pubkey = yk.ssh_cert_fetch_pubkey(&slot).unwrap();

    let ssh_pubkey = PublicKey::from_path(matches.value_of("key").unwrap()).unwrap();
    println!("Signing {ssh_pubkey} with {yk_pubkey}");

    let yk_signer = YubikeySigner {
        slot,
        pin: matches.value_of("pin").unwrap().to_string(),
        mgm_key: hex::decode(matches.value_of("management-key").unwrap()).unwrap(),
    };

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &yk_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal(matches.value_of("principal").unwrap())
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&yk_signer);

    println!("{}", user_cert.unwrap());
}
