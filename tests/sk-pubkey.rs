use sshcerts::ssh::{PublicKey};

#[test]
fn parse_sk_ed25519() {
    let ssh_pubkey = PublicKey::from_string(include_str!("keys/sk/ed25519.pub"));
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(ssh_pubkey.fingerprint().hash, "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA");
}

#[test]
fn parse_sk_ecdsa256() {
    let in_data = include_str!("keys/sk/ecdsa.pub").trim();
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();
    
    assert_eq!(ssh_pubkey.fingerprint().hash, "Ylfgx0U2M9/IVN0+b5/IxdNeVCotsdrRZ5lu5FG2ouc");

    let out_data = format!("{}", ssh_pubkey);
    assert_eq!(in_data, out_data);
}