use sshcerts::ssh::Certificate;

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
