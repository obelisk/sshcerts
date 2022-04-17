use std::env;

use clap::{Arg, Command};

use sshcerts::yubikey::piv::Yubikey;
use sshcerts::yubikey::piv::{AlgorithmId, PinPolicy, RetiredSlotId, SlotId, TouchPolicy};

use std::convert::TryFrom;

fn provision_new_key(
    slot: SlotId,
    subject: &str,
    pin: &str,
    mgm_key: &[u8],
    alg: &str,
    secure: bool,
) {
    let alg = match alg {
        "p256" => AlgorithmId::EccP256,
        _ => AlgorithmId::EccP384,
    };

    println!(
        "Provisioning new {:?} key called [{}] in slot: {:?}",
        alg, subject, slot
    );

    let policy = if secure {
        println!("You're creating a secure key that will require touch to use. Touch Yubikey to continue...");
        TouchPolicy::Always
    } else {
        TouchPolicy::Never
    };

    let mut yk = Yubikey::new().unwrap();
    yk.unlock(pin.as_bytes(), mgm_key).unwrap();
    match yk.provision(&slot, subject, alg, policy, PinPolicy::Never) {
        Ok(pk) => {
            println!("New hardware backed SSH Public Key: {}", pk);
        }
        Err(e) => panic!("Could not provision device with new key: {:?}", e),
    }
}

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

fn main() {
    env_logger::init();
    let matches = Command::new("yk-provision")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("A tool to provision a new key on a yubikey")
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
            Arg::new("pin")
                .help("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .default_value("123456")
                .long("pin")
                .short('p')
                .takes_value(true),
        )
        .arg(
            Arg::new("subject")
                .help("They subject you would like to store in the certificate for later identification")
                .default_value("ykProvisioned")
                .long("subject")
                .short('j')
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
            Arg::new("type")
                .help("Specify the type of key you want to provision (p256, p384)")
                .long("type")
                .short('t')
                .possible_value("p256")
                .possible_value("p384")
                .takes_value(true),
        )
        .arg(
            Arg::new("require-touch")
                .help("Newly provisioned key requires touch for signing operations (touch cached for 15 seconds)")
                .long("require-touch")
                .short('r')
        )
        .get_matches();

    let slot = match matches.value_of("slot") {
        // We unwrap here because we have already run the validator above
        Some(x) => slot_parser(x).unwrap(),
        None => SlotId::Retired(RetiredSlotId::R17),
    };

    let secure = matches.is_present("require-touch");

    provision_new_key(
        slot,
        matches.value_of("subject").unwrap(),
        matches.value_of("pin").unwrap(),
        &hex::decode(matches.value_of("management-key").unwrap()).unwrap(),
        matches.value_of("type").unwrap_or("p384"),
        secure,
    );
}
