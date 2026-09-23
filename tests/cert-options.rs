use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};

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

#[test]
fn parse_check_extensions() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJk",
        "YcbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1",
        "uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzr",
        "AAAAAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAA",
        "AABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE",
        "EEPgOvv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1N",
        "gAAAEgAAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs= key_id");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
    let cert = cert.unwrap();

    assert_eq!(cert.extensions.len(), 5);
    assert_eq!(cert.extensions["permit-agent-forwarding"], "");
    assert_eq!(cert.extensions["permit-user-rc"], "");
    assert_eq!(cert.extensions["permit-port-forwarding"], "");
    assert_eq!(cert.extensions["permit-X11-forwarding"], "");
    assert_eq!(cert.extensions["permit-pty"], "");
}

#[test]
fn signed_cert_reparses_and_reverifies() {
    let private_key = PrivateKey::from_string(concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
        "QyNTUxOQAAACBBvD18M5xE6toNtTkIwVwl7xkJb9DBUSgHfKaKbeTW3gAAAKj3njlq9545\n",
        "agAAAAtzc2gtZWQyNTUxOQAAACBBvD18M5xE6toNtTkIwVwl7xkJb9DBUSgHfKaKbeTW3g\n",
        "AAAEBLyc6RR+xrjQFV9hhmW9z5TYEA4IMVG7+xBq0WHjdnNkG8PXwznETq2g21OQjBXCXv\n",
        "GQlv0MFRKAd8popt5NbeAAAAIW9iZWxpc2tATWl0Y2hlbGxzLU1CUC5sb2NhbGRvbWFpbg\n",
        "ECAwQ=\n",
        "-----END OPENSSH PRIVATE KEY-----",
    ))
    .unwrap();
    let ssh_pubkey = PublicKey::from_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHk1jR7i5Ao85pfz0X6xAWT3N+Wicm17v3UnYw3ZEGnH").unwrap();

    let cert = Certificate::builder(&ssh_pubkey, CertType::User, &private_key.pubkey)
        .unwrap()
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .critical_option("source-address", "127.0.0.1")
        .critical_option("force-command", "/bin/true")
        .set_extensions(Certificate::standard_extensions())
        .sign(&private_key)
        .unwrap();

    let parsed = Certificate::from_string(&cert.to_string()).unwrap();
    assert!(parsed.clone().add_signature(&parsed.signature).is_ok());
}
