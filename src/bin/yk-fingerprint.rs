use std::env;

use rustica_keys::yubikey::ssh_cert_fetch_pubkey;
use rustica_keys::yubikey::{RetiredSlotId, SlotId};

use std::convert::TryFrom;

fn help() {
    println!("Print the SSH key fingerprint for all Yubikey slots");
    println!("Usage: yk-fingerprint");
}

fn main() {
    if env::args().len() > 1 {
        return help();
    }

    println!("Retired Slots:");
    for slot in 0x82..0x95 as u8 {
        let s = RetiredSlotId::try_from(slot).unwrap();
        match ssh_cert_fetch_pubkey(SlotId::Retired(s)) {
            Some(cert) => println!("\t{:?} Got Public Key: {}", s, cert.fingerprint().hash),
            None => println!("\t{:?} No cert found", s),
        }
    }
}