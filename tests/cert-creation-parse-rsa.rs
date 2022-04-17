use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};

// Constants available for multiple tests
const RSA2048_CA_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n",
    "NhAAAAAwEAAQAAAQEAtRTHlBQoQW2O0s0B9C0yNXnNCP7oehwfoKtU/iCfdn9YkxHM/WMe\n",
    "yDZM0rN/xzU/v+pBF860T7v8epUkTToCqdWIf2P8GCstuDGyLELaO79DIWoLskuPm4zUEl\n",
    "6IHweabJFyeXzTiCkSI5HP6rozh2PH/UkGdSBkkff8buSdX//Ej/vEcuRoyV2BGx2qnhNe\n",
    "5OoGdV+itzec1tBAL9HUoIGWUr12T98UV2pjMW/nLD5yYM4V5V9fDbY/zeQeo3cZGnr22M\n",
    "1wL+RSado4PRwYFzj7ch6C4BZp09yRAtypaSrPc4StXxavgKpJgy1PxIFdFKB2Pyg4Zj4N\n",
    "S75V1guBAwAAA9A1Wgm4NVoJuAAAAAdzc2gtcnNhAAABAQC1FMeUFChBbY7SzQH0LTI1ec\n",
    "0I/uh6HB+gq1T+IJ92f1iTEcz9Yx7INkzSs3/HNT+/6kEXzrRPu/x6lSRNOgKp1Yh/Y/wY\n",
    "Ky24MbIsQto7v0MhaguyS4+bjNQSXogfB5pskXJ5fNOIKRIjkc/qujOHY8f9SQZ1IGSR9/\n",
    "xu5J1f/8SP+8Ry5GjJXYEbHaqeE17k6gZ1X6K3N5zW0EAv0dSggZZSvXZP3xRXamMxb+cs\n",
    "PnJgzhXlX18Ntj/N5B6jdxkaevbYzXAv5FJp2jg9HBgXOPtyHoLgFmnT3JEC3KlpKs9zhK\n",
    "1fFq+AqkmDLU/EgV0UoHY/KDhmPg1LvlXWC4EDAAAAAwEAAQAAAQBDmE4n6J5eThdSeVSR\n",
    "YY2siJsREJaXfogP4eUIOAVOpprZy3tJ2wZSlnJ29KpuImJ5sWg7Ct4kJXhKCgJTEaSM4T\n",
    "ji1N/15ahbabGo9Aui4fKdNojHNY2V8yv273LAooXyoRiqYP5VhX9P585FQNybXZP56JiQ\n",
    "gFcKZhfFDXHxs1bHaLeJfGzASoZrpAd1MaHlJPjfDncUevutm3nbbDZtFU4ZYbrPUYhe2B\n",
    "KBuUwunUfab9T5VkMgc3OtPiKGNaCZfMsZmOgyW27Jz0mPzSPsYFev6JifqIWtmaAW0mfu\n",
    "/Mt72CYv75AAQ41NmxDckloBuuPv8/NlCuhBJMEctI2BAAAAgGgXp9ryoHMEwKavUdDKX/\n",
    "0oUk0//95fyUWsw8lqTjAZ4R/QKuJWmelBBnt8E2aSgUsNWorIEBDmbL003TmPwTDIfjvB\n",
    "2JRkbCMov+oN6ZpxPA3s0q55uPhxmuJSOqtzcppJmDpTFJUtmEZKKOnjh6VY2Ea4M7KK5m\n",
    "mwjL3QYDuUAAAAgQDqjC1nnuIwSxH/4JnhRXTpFaTWqbQPm83yj8FhBfyMH6M/pZqkvFvg\n",
    "D1IlqaN+m1214AOHOzW+d8STMBPjnRamGDFvpgN1K23ZOpTqhh0aV4XrfOIUWi8kHbkRpQ\n",
    "HRFdN07JYXefJX4RNgI+khQFsMqhQKfg5jAmbW3MTAiHHkBQAAAIEAxaS2GKlFzAiEBpsD\n",
    "KwdSCb8gCb80Ig+rzFfkxM4EpX89J3mRx9q1WkjCgJE365ShNnqEE1cq1hfM9sfRvWg84g\n",
    "YqVpOwWFNIwMopz1CgWr16bbdIu3RPsU4BMti43qxdRYIJ2vV9amCZR/UyHYagouqUu6wW\n",
    "88Sh/47RYGFMJ2cAAAAZb2JlbGlza0BtaXRjaGVsbHMtbWJwLmxhbgEC\n",
    "-----END OPENSSH PRIVATE KEY-----"
);

// End constants

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ecdsa384_rsa2048ca() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();

    let private_key = PrivateKey::from_string(RSA2048_CA_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    assert!(user_cert.is_ok());
    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "n3kYx3FlLBGcCJWtzkm1YF6vIvtJcp3m+H7u3SnaGxc"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ed25519_rsa2048ca() {
    let ssh_pubkey = PublicKey::from_string(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHHgBVMG7TU30Z8lFfHPwBx98w3wkhoaybFc6/tjasI",
    );
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();

    let private_key = PrivateKey::from_string(RSA2048_CA_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    assert!(user_cert.is_ok());
    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "n3kYx3FlLBGcCJWtzkm1YF6vIvtJcp3m+H7u3SnaGxc"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}
