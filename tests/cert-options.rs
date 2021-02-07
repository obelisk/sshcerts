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