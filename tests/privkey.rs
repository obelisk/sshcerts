use sshcerts::ssh::{PrivateKey, PrivateKeyKind};

use std::io::BufWriter;


#[test]
fn parse_ecdsa_256_private_key() {
    let privkey = include_str!("keys/unencrypted/ecdsa_256_1");

    let privkey = PrivateKey::from_string(privkey);
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "26PWf/RCJx3H/oKI7peJVhnDH/cHTSccHFbFltW7/jk");

    let key = match &privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "008641adbf4f7b49be0646c7bf4a1551f69d9b791ebf836de34ef372e36212a1dc");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/unencrypted/ecdsa_256_1"), serialized);
}

#[test]
fn parse_ecdsa_384_private_key() {
    let privkey = include_str!("keys/unencrypted/ecdsa_384_1");

    let privkey = PrivateKey::from_string(privkey);
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "qFsuxU5ubR/H/GEmI0lWsYuF6llMop6VDYMxov0wNAM");

    let key = match &privkey.kind {
        PrivateKeyKind::Ecdsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "00a9d257b83b370a9194c1dac14095e92838febe98adbf51432c0214369c7fa7e388607177aab95d93d04544f2f3e60e0b");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/unencrypted/ecdsa_384_1"), serialized);
}

#[test]
fn parse_ed25519_private_key() {
    let privkey = include_str!("keys/unencrypted/ed25519_1");

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");

    let key = match &privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "c99da258e0ee67eb68a953a346aaec1e5e4e560dd0af3033bc63a231b6c4b12d33b45500fd4c87480992d6156c2d7fbb3cfda10dbdef2dc064c498d5749b2879");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/unencrypted/ed25519_1"), serialized);
}

#[test]
fn parse_ed25519_private_key_2() {
    let privkey = include_str!("keys/unencrypted/ed25519_2");

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "XfK1zRAFSKTh7bYdKwli8mJ0P4q/bV2pXdmjyw5p0DI");

    let key = match &privkey.kind {
        PrivateKeyKind::Ed25519(key) => key,
        _ => panic!("Wrong key type detected"),
    };
    assert_eq!(hex::encode(&key.key), "fa1e0514dcfb394d57450953bcb93a5b7d5760dc90719cecf70c858ed6ed576dcd097e979599f4411316d7800165ae4665ceba53e72c1222ac82467018ad3e14");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/unencrypted/ed25519_2"), serialized);
}

#[test]
fn parse_rsa_2048_private_key() {
    let privkey = include_str!("keys/unencrypted/rsa_2048_1");

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "A7S6yWfLWgKphtN5UzBbKbhSE71bK/NB6x6NE0DJOpU");

    let key = match &privkey.kind {
        PrivateKeyKind::Rsa(key) => key,
        _ => panic!("Wrong key type detected"),
    };

    assert_eq!(hex::encode(&key.n), "c37ea4f4c97673a0762b4c306bbc56e3ae339543dc0338be8f126113a0f56b35abe35ce01f9990cb77a6b32980e27ef7955e305457e46e9bb733e4c5c7061d38e8dc5f1b883a39599543117e73358fd0e972dcbe15c31dd0e266c3dec8532c5dfa62fdc485be83cc68ff483bc21604e362ace4baea4deca2ab9380d4c536c2be0a00ed6d12206603edfac8c3ae0ac69d4c6fb000ca1e73d164b3632975e654551a710145be411043103bc72f92650452f9748c02d8fa16b07a38de7735a35e241dff13b813c15f28db887b44944c764cd036de06f59bb1e7f93c8d7f1f0dd30ad15710e06c3184d0c126c31a21440ea350fbdedd85cb4acae7a815d7dba1d905");
    assert_eq!(hex::encode(&key.e), "010001");
    assert_eq!(hex::encode(&key.d), "506352678a345825a291f9596be3dd82f04e2bd1e4b5ba6eb99c6028d72633f8b4fee06114fd6bca0f209049bfc2e35ce1a202939c34c5bae861c1700680202217b70eb0de9aba9c78c1447f4fd6b595bd794b062b22b9aefc7a2f8efba71ff66110b5b34b1fe54877e0898e7127e6c8adf9d4707c0aa104df32df661ed67ecb37775f929b57924f6c2163f4bd6b092e31f721bc8c05212ec151fa40d791656dbe5f0a32fa79cf9a6d0b3f5070bfc4375db4cbea7612abd21e772591421e0b38ee14c42b63732a483822edf6cd126079c8653549eddc99a34c8202824587339380b0eb1a6b2d1266a36e978a84d820e4d82d39f9f7bea55c1115da474f33317d");
    assert_eq!(hex::encode(&key.coefficient), "4106d8438d15079e6278ad40e65c4d15d82fd89f1b7369f0831af97df00d16404b0d19d653018f733d2312a12b29cfc6b9156204c08e73f027ddb34deec1b864c3daa292662e8f812ef674eb5ae9e1c824282f380799d9ab6e09c6d4cbb79d7466eed9deebc070651883ca34a0560802dc2ec6710982db945c6a490b6bd3f3bf");
    assert_eq!(hex::encode(&key.p), "f94db898cdfdba0b36d5508c32588ee796f49addabbf408db8c429c448ac7d84b253427434afa31098e36f65b8c9f43722d7f056472f470c0e5520b374140e2887202757b884af88b5c95b6e07d8dc42c8cac5b11067c1923e7d4dda3042e7fcc49e92448bebb3e4a94f387ea4ad81085ec57749c907db676af4bc71bcb0fe2b");
    assert_eq!(hex::encode(&key.q), "c8beeb3574a0d8af760edea0f882e054f72340f39ad61f22db17975fef4725d914e260c8951f125c83955d23be130cecd86cb253e95671b456fa964a6c4567579431e1231924f0a53ea2377738b8d19e6946a1e05b85cf424386bef181de24df066649dafa6437e137c6dec56eb679446a4b486ac9b96bf649789035846b1d8f");

    #[cfg(feature = "rsa-signing")]
    assert_eq!(hex::encode(&key.exp.as_ref().unwrap()), "f6937ca505f8926e4d09a6e543567be16b58fb638c5f5945d31d9201e5af55664dca33cc23e023f4628370c6b78267ddb0c4cb9d4a42e48e740e968d679dfe72ef534a16651637578c15602cefedf9ccc4346a5bbad2248eb4e7d27c9f874d54a054066f6dc4eee496e1180b8a6d61561a064cf9d9afbfbe05f791fb1c9a2289");
    #[cfg(feature = "rsa-signing")]
    assert_eq!(hex::encode(&key.exq.as_ref().unwrap()), "0d8dde81c07b2fc6411965ecc67ac7bcd4e6fb76b748a7d789a58122081cecb04899b46136b85f5c01c26f047fcbf77e726a7c6bf00057330f00626f69fa11ad37235b092ca472df25687c883f3b336417c59e1e70ef8afbf5653eb53dc88b02c802d60fc4024a4799a582db1fcb904a8f46bffffdd8d8324be9a90b0402db7f");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/unencrypted/rsa_2048_1"), serialized);
}
