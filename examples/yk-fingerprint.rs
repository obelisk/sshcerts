use std::env;

use sshcerts::yubikey::piv::Yubikey;
use sshcerts::yubikey::piv::{RetiredSlotId, SlotId};

use std::convert::TryFrom;

fn help() {
    println!("Print the SSH key fingerprint for all Yubikey slots");
    println!("Usage: yk-fingerprint");
}

fn main() {
    if env::args().len() > 1 {
        return help();
    }
    let mut yk = Yubikey::new().unwrap();

    println!("Normal Slots:");
    for slot in [0x9a, 0x9c, 0x9e, 0x9d, 0x9e, 0xf9]
        .iter()
        .map(|x| *x as u8)
    {
        let slot = SlotId::try_from(slot).unwrap();
        match (yk.fetch_subject(&slot), yk.ssh_cert_fetch_pubkey(&slot)) {
            (Ok(subj), Ok(cert)) => {
                let attest = yk.fetch_attestation(&slot);
                println!(
                    "\t{:?}:\t[Fingerprint: {}] [Attest: {}] Subject: [{}]",
                    &slot,
                    cert.fingerprint().hash,
                    if attest.is_ok() { "Yes" } else { "No " },
                    subj
                )
            }
            _ => println!("\t{:?}:\tNo cert found", slot),
        }
    }

    println!("Retired Slots:");
    for slot in 0x82..0x96_u8 {
        let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
        match (yk.fetch_subject(&slot), yk.ssh_cert_fetch_pubkey(&slot)) {
            (Ok(subj), Ok(cert)) => {
                let attest = yk.fetch_attestation(&slot);
                println!(
                    "\t{:?}:\t[Fingerprint: {}] [Attest: {}] Subject: [{}]",
                    slot,
                    cert.fingerprint().hash,
                    if attest.is_ok() { "Yes" } else { "No " },
                    subj,
                )
            }
            _ => println!("\t{:?}:\tNo cert found", slot),
        }
    }
}
