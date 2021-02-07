use ring::{rand, signature};

use sshcerts::ssh::{Certificate, CertType, CriticalOptions, Extensions, PublicKey};
use sshcerts::utils::signature_convert_asn1_ecdsa_to_ssh;

// Constants available for multiple tests
const ECDSA256_CA_PRIVATE_KEY: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02",
    "0101042063b3b4925287d2d20fd53c297ef80cdcd438764d40999ba60f6f1b08",
    "14e3b49ea14403420004dc3f4472cea77335a6ef9ac7bc73a37aac9f234a58d6",
    "0566a1946b135879db89a0a346fbc6f4db9ee5c30380f479280d62c9a65b6f50",
    "81fbc6b6f70048c6290f");

const ECDSA256_SSH_PUBLIC_KEY: &str = concat!(
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy",
    "NTYAAABBBNw/RHLOp3M1pu+ax7xzo3qsnyNKWNYFZqGUaxNYeduJoKNG+8b0257l",
    "wwOA9HkoDWLJpltvUIH7xrb3AEjGKQ8= obelisk@exclave.lan");

const ECDSA384_CA_PRIVATE_KEY: &str = concat!(
    "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020",
    "1010430ed4d1e49a2b25dcde5091f5104d3c1647336ac44afad699728a9f0c9",
    "e3b0ce39b49927f80f38398f72365014b74933c5a16403620004c895d0676a6",
    "a550c09e41bd0b68eea4e6697a060ac43933cb1c544d99155cd93cf2ef9f041",
    "429a99ee3443f6c1a574d00ba03c32cfc23386759ea60f1d43413deb4c86c2f",
    "326fd575b1a2f43e706df2fb6b228275aad698f79aefa622f663e4a");

const ECDSA384_SSH_PUBLIC_KEY: &str = concat!(
    "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAz",
    "ODQAAABhBMiV0GdqalUMCeQb0LaO6k5ml6BgrEOTPLHFRNmRVc2Tzy758EFCmpnu",
    "NEP2waV00AugPDLPwjOGdZ6mDx1DQT3rTIbC8yb9V1saL0PnBt8vtrIoJ1qtaY95",
    "rvpiL2Y+Sg== obelisk@exclave.lan"
);
// End constants

// Test different combinations of public key and cert type
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
fn parse_ecdsa256_key_signed_by_rsa_ca() {
    let cert = concat!(
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgjeWGZiKdnaEOd/VZpzt",
        "ODa61rBFInlJyaiD1Wrey/p0AAAAIbmlzdHAyNTYAAABBBNrlezujx3k21+cb8kDo86oH220fnNFQmkR4mfN9pIq3t5J6AmPXqn2SWeO60hgc9fjZHL4wzFNARcU",
        "i719zbqr+/v7+/v7+/gAAAAEAAAAPb2JlbGlza0BleGNsYXZlAAAACwAAAAdvYmVsaXNrAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9",
        "yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAA",
        "ADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQCneJwoCpZJ98ObYgbAR2na6A44DPVzi2dGKw2LxaG2286Dn7k+ipr+CYF",
        "GscEGnYVNsEEzdibGt3+zeSMhhrBxgH/CJKcp2YHlUr/nAmuJ4DV42nNsTAiwCVZXs0k9K429i+ofNV0R3L81hD3QVQgQrRIMo1EcK9e5Wmtgd3Fz9gxdim04kLz",
        "EDErn8Zw0t+rFulxjWUK1PjnppJbsuXteJt2S8FYGtY+EQ/fUYgm/Yo2ObXYs+hlwvRJuN2fjbhJCCWRazXo2gxL8R9MehdGD6KKIotiBzvINRA0qSLE2rvs8fR6",
        "v7OOK2SvwhwtoFJ3WWU+nUHakMaJJHnH8RwWLOskvsvtFaDX7vrPyG2mCUKsT6k6SLAbBEhCm5kFROWmZ9xFk7Tf6FVhhm0OUUt79O/O+DlhzphOKIfgGLK5+CQ5",
        "Xa7a8o3N8sqjyrVESchGIgetA3oCErD/b6RUgd9aS4D/ggXWlLer1J/BtLTv2vY2MYTa0SYyTZXmK8lHXI3UAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYCHdLBNZG/",
        "OdM//93gYb+0UbVwpqI7d/v1VMV6+yjkuT3lIQPYajY/cXI2RTgQNXebdYOGVP+xguUMvn8W1G/udYQscMKPuQt6UAj/ZUOWRuoQ0uHocQXyUza9+dk3uWRNHUNM",
        "zPvinYRjwxco+bMPw6zU1MVtOErE0jS2NXJFxwZm1TLCzvHFxW38jMwUA1ATt7U4zM8h7dNwzfQvFq/FHXWuo77SEpcOtijDXdot0y57DRFiGqK2TYPGXPO5CChS",
        "dPH+gYcruPF4vEAV/t/yXeoRz6y68LcgBKh/hzslQuwDJelqDvlJp2d+++jf49s0KjZGbWJLYwfOCSRm+EN3TYGEuTU23XXbTHXZnFLT08EKvHhtfdD3CXOtU2LX",
        "bikWw2QEnG0hvdXSMTk8257uMS2XDgVZoZTXUJUWlqH/tCcmVp0pUlNhke1qTfV8ovAMcTxG9M6oEpEJqFJzmVwOlk3b8qUMp+eJtXPBIZa5oqYEkgVHCvchTgDz",
        "PVfHUXEo= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(cert.key.fingerprint().hash, "calfKUhj4a4YcDOB3F0dPZrvzVAQHfw438eQcbk7Aw0");
    assert_eq!(cert.signature_key.fingerprint().hash, "AOyFjjStJTWt5/f0w/aVcuxtYmVbDAepkBcMKhpfhUc");
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
fn parse_ecdsa256_key_signed_by_ecdsa256_ca() {
    let cert = concat!(
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAghZWs9kzFksOzb8D65r6",
        "hlgkhE/9XlybNXz63RkO+QcwAAAAIbmlzdHAyNTYAAABBBNrlezujx3k21+cb8kDo86oH220fnNFQmkR4mfN9pIq3t5J6AmPXqn2SWeO60hgc9fjZHL4wzFNARcU",
        "i719zbqr+/v7+/v7+/gAAAAEAAAAPb2JlbGlza0BleGNsYXZlAAAACwAAAAdvYmVsaXNrAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9",
        "yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAA",
        "ADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH74uf5G1q/e9nyB3RfO8xP5ACTQG+7brIj",
        "hL8o312/kG6wakswegIdUnn1UK6+oybd1B+wkYYH2h2fjKq3MaTUAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIARPhwBgbO8ymqtOtQjocjfXT+h",
        "a4KKW+LkdI4aeD6MgAAAAIQCoHGxdoVmQOZzXuW0y7WWy1pOjwvVBfHb83shY/7awQg== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(cert.key.fingerprint().hash, "calfKUhj4a4YcDOB3F0dPZrvzVAQHfw438eQcbk7Aw0");
    assert_eq!(cert.signature_key.fingerprint().hash, "Ch3IQ5MgZReoB1OFWwI3BhJi+1QILiHQaH7eVUbhg3M");
}

#[test]
fn parse_ecdsa384_key_signed_by_ecdsa384_ca() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAggFY93I7vBDRz+bIyQ4",
        "46IgWTAF4aKIQolQ7vEk4WkuAAAAAIbmlzdHAzODQAAABhBPMEN9vjk73w0OERXZVSLN1cnTxQ8B3nD7vHBOnwMHcPW0nYoBVZFAf45jwAcdPDCYkLweq6IXVEK",
        "cvzXTtfZEzO4bmJAjC/3ecYz/XLY++PlubxVtGLgbUbRuIHALx5yf7+/v7+/v7+AAAAAQAAAA9vYmVsaXNrQGV4Y2xhdmUAAAAXAAAAB29iZWxpc2sAAAAIbWl0",
        "Y2hlbGwAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAA",
        "WcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAIgAAAATZWNkc2Etc2hhMi1uaX",
        "N0cDM4NAAAAAhuaXN0cDM4NAAAAGEENS4+j+Lm0PGBjuWvNiCzb2ECZ4p5tTeH8QXXMzhmxTGM+OG2TZ6SuNU0LEp5ZCreJ5T2kpbWcQJlUu225V/xkp4rVqk6T",
        "7J+677swPlgNXkrRMQWV0XCJ1yPm2u2khUxAAAAgwAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAAaAAAADBr5QLuE6JokDp98u8/Euc+mmJehMWGn6t3ONhBfXed",
        "5LDFQw2XOHIInulSrr9WalcAAAAwQkTFMYofbJleAoDxyODxiL6qLutw0Lq3LwSPGE7rjQ1NHV1qDoYLu0BXIw1w7Kbu obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ecdsa256_key_signed_by_ecdsa384_ca() {
    let cert = concat!(
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg+3JCnUufgieiQ9C6Ak",
        "gs/rB12m3pL6jqmfOysplrRKMAAAAIbmlzdHAyNTYAAABBBBU97EFBNEhImj36GAyM7Tfq/1Tk/jTIPx+3De9KVyrzo6vaUK5hLCCKyabm4P7LDeq0bwnt52CiR",
        "tO//C2Gh9v+/v7+/v7+/gAAAAEAAAAPb2JlbGlza0BleGNsYXZlAAAAFwAAAAdvYmVsaXNrAAAACG1pdGNoZWxsAAAAAAAAAAD//////////wAAAAAAAACCAAAA",
        "FXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnB",
        "lcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDUuPo/i5tDxgY",
        "7lrzYgs29hAmeKebU3h/EF1zM4ZsUxjPjhtk2ekrjVNCxKeWQq3ieU9pKW1nECZVLttuVf8ZKeK1apOk+yfuu+7MD5YDV5K0TEFldFwidcj5trtpIVMQAAAIUAA",
        "AATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAGoAAAAxALRWcN6wcjyQ/yv5oN+FnrQvH9pdqVKlHZ3+mseGM5X99gIao+icfLOl3i/PiGg9KQAAADEAytl8wuUT47LI",
        "zxRyeLXJTPI0FKH8fmsDcKYxCK3TVi7zXJBgX8yp+UHWuPQ5BcTb obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ecdsa384_key_signed_by_ecdsa256_ca() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgBGLKTeODIcULXUB5ts",
        "AwQVxxSX+zSLdM1HB0/pBMu6EAAAAIbmlzdHAzODQAAABhBPMEN9vjk73w0OERXZVSLN1cnTxQ8B3nD7vHBOnwMHcPW0nYoBVZFAf45jwAcdPDCYkLweq6IXVEK",
        "cvzXTtfZEzO4bmJAjC/3ecYz/XLY++PlubxVtGLgbUbRuIHALx5yf7+/v7+/v7+AAAAAQAAAA9vYmVsaXNrQGV4Y2xhdmUAAAAXAAAAB29iZWxpc2sAAAAIbWl0",
        "Y2hlbGwAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAA",
        "WcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaX",
        "N0cDI1NgAAAAhuaXN0cDI1NgAAAEEElE7ftbqALyhLNqUSjxKvHKVLtA2Pr8ysRYx5NP4B3PTxeMGO5QNYZ6Cd5QUSp49tI5zoggPI/Cy3ZZnPL62bSAAAAGQAA",
        "AATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEkAAAAgKH2/x4fHYWuVW/jJG1tPj3Q5rVo3cHSFsE/a7IuxZOwAAAAhALRLYKIG1dXFB+ePwtA1Qeey9r+mOFre7GPg",
        "ApJvAcJL obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_ed25519_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIK8bQbhlLJcUXYHcTA2FkU6qDvY4f9IXO3PMBMT",
        "zR76hAAAAIB7fwcuszYuMUHSRn/Jgx0R5o8440VO5fuRzFwz6gBpv/v7+/v7+/v4AAAABAAAAD29iZWxpc2tAZXhjbGF2ZQAAABcAAAAHb2JlbGlzawAAAAhtaXR",
        "jaGVsbAAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZ",
        "wZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACB",
        "F8fjQjhPiIQoIpSZUQJCrjBCqLOanQPT9T2VDzoYySAAAAFMAAAALc3NoLWVkMjU1MTkAAABAQQtSUBHzgzLEYLcuYmtZlVz2guW9141tmzSjWnDKrPv07r2W0BB",
        "cMvF5LlgHwzQN3iY4gfCrfaUF6UW58P/ADg== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_check_critical_options() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMfkr8HI/IgjjxXbqjKFUkrbmar75c179HDc++",
        "r2t5nsAAAAIB7fwcuszYuMUHSRn/Jgx0R5o8440VO5fuRzFwz6gBpv/v7+/v7+/v4AAAABAAAAD29iZWxpc2tAZXhjbGF2ZQAAABcAAAAHb2JlbGlzawAAAAhta",
        "XRjaGVsbAAAAAAAAAAA//////////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAA",
        "AAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXV",
        "zZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgRfH40I4T4iEKCKUmVECQq4wQqizmp0D0/U9lQ86GMkgAAABTAAAAC3NzaC1lZDI1NTE5AAAAQG",
        "177VlVbAR36GpGzTor6r0q6kkpobH8g/JRoNzAe6CRgz5b202PpA61gCw/kgR8qY7wDaRu9MYNTUnvPRGYGgc= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();

    assert_eq!(cert.critical_options.len(), 1);
    assert_eq!(cert.critical_options["force-command"], "/bin/true");
}



// Test PublicKey parsing
#[test]
fn parse_ecdsa256_publickey() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(ssh_pubkey.fingerprint().hash, "BAJ7Md5+hfu6I6ojHoJpSNVXNRnxM8XfNnA8Pf1X/2I");
}

// Test signing and parsing work together
fn test_ecdsa256_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let pkcs8_bytes = hex::decode(ECDSA256_CA_PRIVATE_KEY).unwrap();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();
    let rng = rand::SystemRandom::new();
    let signature = key_pair.sign(&rng, buf).unwrap();

    let sig_type = "ecdsa-sha2-nistp256";
    let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(sig_type.as_bytes());
    encoded.extend(signature_convert_asn1_ecdsa_to_ssh(&signature.as_ref()).unwrap());

    Some(encoded)
}

// Test signing and parsing work together
fn test_ecdsa384_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = hex::decode(ECDSA384_CA_PRIVATE_KEY).unwrap();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let signature = key_pair.sign(&rng, buf).unwrap();

    let sig_type = "ecdsa-sha2-nistp384";
    let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(sig_type.as_bytes());
    encoded.extend(signature_convert_asn1_ecdsa_to_ssh(&signature.as_ref()).unwrap());

    Some(encoded)
}

#[test]
fn create_sign_parse_verify_ecdsa256() {
    use std::collections::HashMap;

    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert = Certificate::new(
        ssh_pubkey.clone(),
        CertType::User,
        0xFEFEFEFEFEFEFEFE,
        String::from("key_id"),
        vec![String::from("obelisk")],
        0,
        0xFFFFFFFFFFFFFFFF,
        CriticalOptions::None,
        Extensions::Standard,
        ca_pubkey.clone(),
        test_ecdsa256_signer,
    );

    assert!(user_cert.is_ok());

    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn create_sign_parse_verify_ecdsa384() {
    use std::collections::HashMap;

    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(&ECDSA384_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert = Certificate::new(
        ssh_pubkey.clone(),
        CertType::User,
        0xFEFEFEFEFEFEFEFE,
        String::from("key_id"),
        vec![String::from("obelisk")],
        0,
        0xFFFFFFFFFFFFFFFF,
        CriticalOptions::None,
        Extensions::Standard,
        ca_pubkey.clone(),
        test_ecdsa384_signer,
    );

    assert!(user_cert.is_ok());

    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);
}