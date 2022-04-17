use sshcerts::ssh::Certificate;

#[test]
fn parse_rsa_key_signed_by_rsa_ca() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com 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",
        "YvptuJgGi/IMrA1SmB8Uj6WF++HcbvLdBtpcQGY= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(
        cert.key.fingerprint().hash,
        "HgEyuGUL94jKMFSFdg3WoGRwIaxVsH7/Js0IBrUvjRQ"
    );
    assert_eq!(
        cert.signature_key.fingerprint().hash,
        "AOyFjjStJTWt5/f0w/aVcuxtYmVbDAepkBcMKhpfhUc"
    );
}

#[test]
fn parse_rsa_key_signed_with_ssh_rsa() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com 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");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(
        cert.key.fingerprint().hash,
        "S/Ea2GOGCB3puuIITmkOFR1RqsVpp7uv4J5JD1rwgqI"
    );
    assert_eq!(
        cert.signature_key.fingerprint().hash,
        "S/Ea2GOGCB3puuIITmkOFR1RqsVpp7uv4J5JD1rwgqI"
    );
}

#[test]
fn parse_rsa_key_signed_by_ecdsa384_ca() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgTf3qsIa8N5ClFLijbBBPQxqtfoOKfbrw661HwDn1U4cAAAA",
        "DAQABAAABAQDfWvPz9gZT1M7rBZws4VKq1hczl5cWa27lhXhUH0/wBJyGEZ2dNUcH0EuLqkSg3zwS56jxeW/IKHv9ER96tmFAOulQgqz5Y6BoftZE8vp8pqoAdUY",
        "QCDx0PkL+FbsuIEQMn2pOnHPDfGMgoE+6AC+OSPQV0SLunK0qVa4LsulEu0O3u+ujiUMFf6IPzNKUwsbgpx5TslvZVAr8caoEKfSTJ5huVHdZM+2EHCfY6Zj4Kxi",
        "DT1uOUl33UeYDnvz9ovw0xT0dsfX6tDfEdc5EGMSO0lde+oJIoQw51+RWwJik1z1fVDQIXguNayfEQoidvDrAprUQZtsvZ1d7AyadEWuT/v7+/v7+/v4AAAABAAA",
        "ADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA//////////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGV",
        "ybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl",
        "0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAIgAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEPp4/OyXuKLSbDPlJ23D",
        "9h0q8E9+9o68wVFcMTdInpQimgG6o+l/VoJQLNxkzd48BNt4riB4Il8EPcMb0g3fkAN6eSqo14qn6BEbtuJ9bINdxU35GmC1bZgzsgod3Ok48AAAAhAAAABNlY2R",
        "zYS1zaGEyLW5pc3RwMzg0AAAAaQAAADEAgTJrs88huubcWt8xkvcMVJC5zDBoRjKCHbgZeobH0gwudZfmhPwAEHqJtpIXEMlmAAAAMBtHZOZZDEWn3OklGIDbK6e",
        "dvBKClGK9O1wHwn34UddoFwYeUA7szDGz3DWpyrXbTg== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(
        cert.key.fingerprint().hash,
        "PcLn3Di2x3rrbLQM7QQGA3JHGr6RsT9N7aTaK9B54Xw"
    );
    assert_eq!(
        cert.signature_key.fingerprint().hash,
        "xOwDaE2Z4bv6lUFLvoT87Hf2WGgy/zIP0Av7dIlWT5E"
    );
}

#[test]
fn parse_rsa_key_signed_by_ecdsa256_ca() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgvKYUoYQRh64jtxcuQBn344N+Vf551B02clPEYFZUBQkAAAA",
        "DAQABAAABgQC3DH/PBs33u8Tiz1g+NNa806fNW2cEjgUedehBGeRAURFE33n4BgIn3F6Z3GN/319bHSjooMCeBYW2lPLdujTYZdpa6zEv/JzT9FANGN9/yOhYjQd",
        "z6PK0fjXc/EKfMOLtxO7RA1NRPYOwz6TwLGSohBvy1keACdzKNzPV45DsaN1wkUqOUAJLOp0SB5SuF0Q7NDsaRw+JrGvVn+5iYhoLC9+2+0/FGJZNDazjXbKMhCZ",
        "tnbze1R7lz0tMcp6E9VJRcjueeAd3zjQRnhvAarg6F7/GYZ6Bi4Wi7yRw5ROIpROtkRah4pfnpSZnQgbdwja+GCBV1d0lFNPC8YxoN4TxRfVRhH8OchZjkslQGjM",
        "I9L9pkNR1DkE00FYzGg7EgWuq3dPev8cVZbsh/4DjTHBjdHVnl5FCib00vwxjGAlC9+RtupV99WvPHE+l3MF1QxvxQC1uJLUkfLXi0fUqNYFCSRnbySIh6VBA8FX",
        "z1dZ6vJifA0+2Bz4wniJEjgqDRuX+/v7+/v7+/gAAAAEAAAAPb2JlbGlza0BleGNsYXZlAAAACwAAAAdvYmVsaXNrAAAAAAAAAAD//////////wAAAAAAAACCAAA",
        "AFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnB",
        "lcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH74uf5G1q/e9ny",
        "B3RfO8xP5ACTQG+7brIjhL8o312/kG6wakswegIdUnn1UK6+oybd1B+wkYYH2h2fjKq3MaTUAAABlAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABKAAAAIQCR0b5",
        "cCUZlRWmASl/v2O7PE6qWjD9xtbS5RBPsUG/fCAAAACEAtn99KzQjulXoxYbRO0Tt6SJo1JVRZSNiFvKFa+h3/kA= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(
        cert.key.fingerprint().hash,
        "HgEyuGUL94jKMFSFdg3WoGRwIaxVsH7/Js0IBrUvjRQ"
    );
    assert_eq!(
        cert.signature_key.fingerprint().hash,
        "Ch3IQ5MgZReoB1OFWwI3BhJi+1QILiHQaH7eVUbhg3M"
    );
}

#[test]
fn parse_rsa_key_signed_by_ed25519_ca() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgmwGja+0f+nu1QDYkVfGwzwCeAyKFv1r7fbaqUNLZA3QAAAA",
        "DAQABAAABAQDfWvPz9gZT1M7rBZws4VKq1hczl5cWa27lhXhUH0/wBJyGEZ2dNUcH0EuLqkSg3zwS56jxeW/IKHv9ER96tmFAOulQgqz5Y6BoftZE8vp8pqoAdUY",
        "QCDx0PkL+FbsuIEQMn2pOnHPDfGMgoE+6AC+OSPQV0SLunK0qVa4LsulEu0O3u+ujiUMFf6IPzNKUwsbgpx5TslvZVAr8caoEKfSTJ5huVHdZM+2EHCfY6Zj4Kxi",
        "DT1uOUl33UeYDnvz9ovw0xT0dsfX6tDfEdc5EGMSO0lde+oJIoQw51+RWwJik1z1fVDQIXguNayfEQoidvDrAprUQZtsvZ1d7AyadEWuT/v7+/v7+/v4AAAABAAA",
        "ADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA//////////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGV",
        "ybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl",
        "0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM7RVAP1Mh0gJktYVbC1/uzz9oQ297y3AZMSY1XSbKHkAAAB",
        "TAAAAC3NzaC1lZDI1NTE5AAAAQHkF7vM7TlQxDd3tsII6OJBJJ9wOfDdnmUwIlSwb5SvRmxqG8o0trZHz3OVQbszJpjSAYCD2uW/toAcd+KpxqA0= obelisk@ex",
        "clave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(
        cert.key.fingerprint().hash,
        "PcLn3Di2x3rrbLQM7QQGA3JHGr6RsT9N7aTaK9B54Xw"
    );
    assert_eq!(
        cert.signature_key.fingerprint().hash,
        "QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M"
    );
}
