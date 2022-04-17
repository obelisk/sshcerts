use sshcerts::ssh::Certificate;

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
