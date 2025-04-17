use std::env;

use clap::{Arg, Command};

use sshcerts::yubikey::piv::Yubikey;
use sshcerts::yubikey::piv::{RetiredSlotId, SlotId};

use x509_parser::prelude::*;

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

/// This routine will generate a new PIV key and use the new key to create a CSR signer.
/// Then use this CSR signer to sign a random blob and then verify the signature.
fn main() {
    env_logger::init();
    let matches = Command::new("yk-generate-csr")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Thanh Nguyen <thanh@timweri.me")
        .about("A tool to create certificate signer on a Yubikey")
        .arg(
            Arg::new("slot")
                .help("Numerical value for the slot on the yubikey to use for your private key")
                .long("slot")
                .short('s')
                .required(true)
                .validator(slot_validator)
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
        .arg(
            Arg::new("pin")
                .help("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .default_value("123456")
                .long("pin")
                .short('p')
                .takes_value(true),
        )
        .get_matches();

    let slot = match matches.value_of("slot") {
        // We unwrap here because we have already run the validator above
        Some(x) => slot_parser(x).unwrap(),
        None => SlotId::Retired(RetiredSlotId::R17),
    };
    let pin = matches.value_of("pin").unwrap();
    let mgm_key = &hex::decode(matches.value_of("management-key").unwrap()).unwrap();

    let mut yk = Yubikey::new().unwrap();
    yk.unlock(pin.as_bytes(), mgm_key).unwrap();

    let csr = yk.generate_csr(&slot, "TestCSR").unwrap();

    let (_, parsed_csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
    parsed_csr.verify_signature().unwrap();
}
