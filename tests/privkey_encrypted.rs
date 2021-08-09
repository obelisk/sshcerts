use sshcerts::ssh::{PrivateKey, PrivateKeyKind};


#[test]
fn parse_encrypted_ed25519_private_key() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAMSH2ak6
+qM0Od6QYgqk3EAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJLaNw1wt2GAGxhZ
b4TTQ3m5bWeghg0hVbUBie2IDxb1AAAAoJgXZeSQFgSB0JzfMPBB9l1roV4nZnAVG0aUC4
oVhmOX/jGK2MRLusepo1tF98kou01dbVTKiZYdxrCffJDYj2H2LrtWqR2sf19mhUY0OrW8
0inHLPw5CRRPCJuZ8fdmsbtawWlajCmJykrtCLAhiUx4dJ2gYLyaSIFbFhg0B9XhuLHQ09
gj+HqUxSiAOuRA5cDU+SykIfb7TLvteZOpl2I=
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "bTkq+BEqfkYOgyPk2ziLwtkxDFcj531SfwEpl3IyutU");

    let key = match privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(
        key.key,
        hex::decode("697DEA3B53C8612F87DC06E92A466366866458403D9695040AD341D05D7430E692DA370D70B761801B18596F84D34379B96D67A0860D2155B50189ED880F16F5").unwrap(),
    )
}

#[test]
fn parse_encrypted_ed25519_private_key_32_rounds() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABArNg8tIr
sFX6oNT1jNqVoIAAAAIAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEofsz/Ssr2U3p81
fVIYsF8uRX1qKxk5olZhhtWEcK+lAAAAoCJJBzCtLwWY0cx7G1zYbvbjUP4/lIryQEufgZ
DrhYqWabR+nO8Os2U9EumbuqVM81Rrxcc1Qc9k/IDUelhGDubO7kRFDzn3BAirKl2sTADx
JcR8y21R5hqNGhTlx0F8kqAGg2nW3PmsiGCwKl7Iz7IMf4iaUuufHG2RtTaFpN0n9gxbpQ
6xceKSL0Ba+hjMl54kebsfZJfwgdh6fZ8leec=
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "nTCuabo74eqb8zYiqsg8x7sfgzsu1Egv0XGzaiip9XU");

    let key = match privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(
        key.key,
        hex::decode("C9753EE1FE006557E290E5EBBC67D75E9DDFC9F647291E3E89B23A83507CF5774A1FB33FD2B2BD94DE9F357D5218B05F2E457D6A2B1939A2566186D58470AFA5").unwrap(),
    )
}

#[test]
fn parse_encrypted_ec256_private_key() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAgyk4Wlj
Nok6umgT5cd/0lAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBPsoWTQSrnuRXj3a7232/SuLOIOva1RHTtmVcRpt3+ktr20hXisf4RG9LB
TZkZ9q0JjvJybRpXo4mT8pVS0jQIIAAACwYyMrnR4LZovfZSMEcdxdPgwM/sioaaLyI7eb
Kh4cPIS2TRZ6a8SlF/+ugnz/5kvQyazJhp07fMqusB/v+7x/jmcNs7z1aq6rh39sirf7ll
kA+bCsY/r/A5G8bcYiIUbRpFIY+JXJkvv1aXIsRS+K5OXKb9aySrBddTY3Uddp9WkfG72W
Gd5VYX4HxsQZWQixs9DSZyCexueq7Fw+57AW9z1XFySUhHdiRlgeXSxsF8Q=
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "aeK6cuLIzfIddiLtlP+kaZqA5lo4ExdXM8ksWeJPPp8");

    match privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
}

#[test]
fn parse_encrypted_ec384_private_key() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDx+U4gFb
XXB+awGkd75t8qAAAAEAAAAAEAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlz
dHAzODQAAABhBFlMgDDsgzBqyzJoiM0nS0SZ2oxXBGkYcyaZ7Y3m5CO4BsUIWcHIEJ3A8D
pftOVAmlRm2El4szGmwJrfgBLVF0JfqjQdTrQBG4ARRAWZCbSF7E0VWLYZOHKZZqAlrxKV
eAAAAOCiWpA95P/h4YkK1Qm7C04rlstJFrjTqiVe0vg1XZ/j+4oFfKb5lZA8MbKv6QTP2Q
fD4nMprI5/QXpi0jI/Po0FUJecY+xNTLzTohhwaLkg7aztAQAsChsW8txfetTkFsqz0RxI
VPIGbXHVwMdRPbheRu9AOOotSJldENE5jpdQ9PuBj0IIYw/Q3ZVlT+fePQqxsJsfk820X1
qE7mF1LNXlV52YOTwFvwfEwiUYyDnhVvwiR06q0ojtlz/K/9t7W+yXNWK55LduI7Q7WaDn
N9Rg7yGs2leAkts+8G8w+tgJJQ==
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "SvNs3N/ZVtfktcRjlcgpvOs4qFnQTIVGTt2L2S2nVI8");

    match privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
}

#[test]
fn parse_encrypted_rsa3072_private_key() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
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
cRts9Ge+2sCv9AYgd/SipxopCqw=
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "+fZGegm7Lmc5SJJQRXZjvWhT25Ybqb8H4Vvq91Z1JEY");

    match privkey.kind {
        PrivateKeyKind::Rsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
}

#[test]
fn parse_encrypted_ed25519_private_key_bad_passphrase() {
    let privkey = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAMSH2ak6
+qM0Od6QYgqk3EAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJLaNw1wt2GAGxhZ
b4TTQ3m5bWeghg0hVbUBie2IDxb1AAAAoJgXZeSQFgSB0JzfMPBB9l1roV4nZnAVG0aUC4
oVhmOX/jGK2MRLusepo1tF98kou01dbVTKiZYdxrCffJDYj2H2LrtWqR2sf19mhUY0OrW8
0inHLPw5CRRPCJuZ8fdmsbtawWlajCmJykrtCLAhiUx4dJ2gYLyaSIFbFhg0B9XhuLHQ09
gj+HqUxSiAOuRA5cDU+SykIfb7TLvteZOpl2I=
-----END OPENSSH PRIVATE KEY-----"#;

    let privkey = PrivateKey::from_string_with_passphrase(privkey, Some(format!("Test")));
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_err());
}