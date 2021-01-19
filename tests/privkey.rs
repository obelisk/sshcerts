use rustica_keys::ssh::{PrivateKey, PrivateKeyKind};


#[test]
fn parse_ecdsa_384_private_key() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQQUPB58xc9cxcLp1swjJ87XjD2butH5\n",
        "blSJ+VPO+/ZV+yFn7ElXIRzvm+i2aPj0/fc54LSdE8SZlAu7RLuyAgwH8IqfhLATG3mq7f\n",
        "DPSnRSn7zErjIUGOvRS7g5vhBH9R0AAADgGCxIIhgsSCIAAAATZWNkc2Etc2hhMi1uaXN0\n",
        "cDM4NAAAAAhuaXN0cDM4NAAAAGEEFDwefMXPXMXC6dbMIyfO14w9m7rR+W5UiflTzvv2Vf\n",
        "shZ+xJVyEc75votmj49P33OeC0nRPEmZQLu0S7sgIMB/CKn4SwExt5qu3wz0p0Up+8xK4y\n",
        "FBjr0Uu4Ob4QR/UdAAAAMQCp0le4OzcKkZTB2sFAlekoOP6+mK2/UUMsAhQ2nH+n44hgcX\n",
        "equV2T0EVE8vPmDgsAAAATb2JlbGlza0BleGNsYXZlLmxhbgECAwQ=\n",
        "-----END OPENSSH PRIVATE KEY-----");

    let privkey = PrivateKey::from_string(privkey);
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "qFsuxU5ubR/H/GEmI0lWsYuF6llMop6VDYMxov0wNAM");

    let key = match privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "00a9d257b83b370a9194c1dac14095e92838febe98adbf51432c0214369c7fa7e388607177aab95d93d04544f2f3e60e0b");
}
