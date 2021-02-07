use sshcerts::ssh::{PrivateKey, PrivateKeyKind};


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

#[test]
fn parse_ecdsa_256_private_key() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQWBFNpmjacrlnUn4wMQzt7OTY6iwkf\n",
        "hRR5gA6N7HaGZdd2pUwxyKaCbsH5ArDYTb+YCzrAmO+pibJ9qCdXr6MqAAAAsKCPNjagjz\n",
        "Y2AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYEU2maNpyuWdSf\n",
        "jAxDO3s5NjqLCR+FFHmADo3sdoZl13alTDHIpoJuwfkCsNhNv5gLOsCY76mJsn2oJ1evoy\n",
        "oAAAAhAIZBrb9Pe0m+BkbHv0oVUfadm3kev4Nt407zcuNiEqHcAAAAE29iZWxpc2tAZXhj\n",
        "bGF2ZS5sYW4BAgME\n",
        "-----END OPENSSH PRIVATE KEY-----");

    let privkey = PrivateKey::from_string(privkey);
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "26PWf/RCJx3H/oKI7peJVhnDH/cHTSccHFbFltW7/jk");

    let key = match privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "008641adbf4f7b49be0646c7bf4a1551f69d9b791ebf836de34ef372e36212a1dc");
}

#[test]
fn parse_ed25519_private_key() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
        "QyNTUxOQAAACAztFUA/UyHSAmS1hVsLX+7PP2hDb3vLcBkxJjVdJsoeQAAAJgzkRiyM5EY\n",
        "sgAAAAtzc2gtZWQyNTUxOQAAACAztFUA/UyHSAmS1hVsLX+7PP2hDb3vLcBkxJjVdJsoeQ\n",
        "AAAEDJnaJY4O5n62ipU6NGquweXk5WDdCvMDO8Y6IxtsSxLTO0VQD9TIdICZLWFWwtf7s8\n",
        "/aENve8twGTEmNV0myh5AAAAE29iZWxpc2tAZXhjbGF2ZS5sYW4BAg==\n",
        "-----END OPENSSH PRIVATE KEY-----");

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");

    let key = match privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "c99da258e0ee67eb68a953a346aaec1e5e4e560dd0af3033bc63a231b6c4b12d33b45500fd4c87480992d6156c2d7fbb3cfda10dbdef2dc064c498d5749b2879");
}

#[test]
fn parse_ed25519_private_key_2() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
        "QyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FAAAAJiT9ajkk/Wo\n",
        "5AAAAAtzc2gtZWQyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FA\n",
        "AAAED6HgUU3Ps5TVdFCVO8uTpbfVdg3JBxnOz3DIWO1u1Xbc0JfpeVmfRBExbXgAFlrkZl\n",
        "zrpT5ywSIqyCRnAYrT4UAAAAE29iZWxpc2tAZXhjbGF2ZS5sYW4BAg==\n",
        "-----END OPENSSH PRIVATE KEY-----");

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "XfK1zRAFSKTh7bYdKwli8mJ0P4q/bV2pXdmjyw5p0DI");

    let key = match privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "fa1e0514dcfb394d57450953bcb93a5b7d5760dc90719cecf70c858ed6ed576dcd097e979599f4411316d7800165ae4665ceba53e72c1222ac82467018ad3e14");
}