use sshcerts::ssh::Certificate;

#[test]
fn parse_rsa_key_signed_by_rsa_ca() {
    let cert = concat!(
        "ssh-rsa-cert-v01@openssh.com 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",
        "YvptuJgGi/IMrA1SmB8Uj6WF++HcbvLdBtpcQGY= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(cert.key.fingerprint().hash, "HgEyuGUL94jKMFSFdg3WoGRwIaxVsH7/Js0IBrUvjRQ");
    assert_eq!(cert.signature_key.fingerprint().hash, "AOyFjjStJTWt5/f0w/aVcuxtYmVbDAepkBcMKhpfhUc");
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
    assert_eq!(cert.key.fingerprint().hash, "PcLn3Di2x3rrbLQM7QQGA3JHGr6RsT9N7aTaK9B54Xw");
    assert_eq!(cert.signature_key.fingerprint().hash, "xOwDaE2Z4bv6lUFLvoT87Hf2WGgy/zIP0Av7dIlWT5E");
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
    assert_eq!(cert.key.fingerprint().hash, "HgEyuGUL94jKMFSFdg3WoGRwIaxVsH7/Js0IBrUvjRQ");
    assert_eq!(cert.signature_key.fingerprint().hash, "Ch3IQ5MgZReoB1OFWwI3BhJi+1QILiHQaH7eVUbhg3M");
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
    assert_eq!(cert.key.fingerprint().hash, "PcLn3Di2x3rrbLQM7QQGA3JHGr6RsT9N7aTaK9B54Xw");
    assert_eq!(cert.signature_key.fingerprint().hash, "QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
}