use sshcerts::ssh::PublicKey;

#[test]
fn parse_ed25519_publickey() {
    let in_data = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH447ysO2G10q6wS6KveQWYJNr7Ux5WjtbDJr/MQ4Xpw obelisk@exclave.lan";
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "c4X5mQt9f37ZkdQUbNckivACZmY52rZw0jJUCA1DfkI"
    );

    let out_data = format!("{}", ssh_pubkey);
    assert_eq!(in_data, out_data);
}

#[test]
fn parse_ecdsa384_publickey() {
    let in_data = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCVw+mPwQPcohKD0L9hDOfbtzMvBUq7WE4RQZ2y7j4dMhdww0Ux0rv3gbhTsvL8GbrfZLOwVkra3WEY1qBDGPLGn1Ym6RLWMqo5qHBjcyDJZGzG0+bAa7np6mtU7ydpkvw== obelisk@exclave.lan";
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "huOgP+FbGDQ830OcBfh2j3WwGn+E66sxfZp3NwXA4jg"
    );

    let out_data = format!("{}", ssh_pubkey);
    assert_eq!(in_data, out_data);
}

#[test]
fn parse_ecdsa256_publickey() {
    let in_data = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan";
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "BAJ7Md5+hfu6I6ojHoJpSNVXNRnxM8XfNnA8Pf1X/2I"
    );

    let out_data = format!("{}", ssh_pubkey);
    assert_eq!(in_data, out_data);
}

#[test]
fn parse_rsa4096_publickey() {
    let ssh_pubkey = PublicKey::from_string("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDUq0+iU7PeaeE6HPYX5bluxcZKWyFel1pR0P3367gWvAjCtqYu6yl+2K5S4GVnoFc1VaezI37dInsRdha6kGyOBudepm4XJOMZXKsgeBUTVIXzSHoexeb+C6Plp8naxOt+462eOpuLcxbp/62WfKYe1xQTfmTHHQG0TSwoz53G2RKxPQaimka0rhb4vGsQR2/DKkXoxQX26aRWPliKKFhh43NfercVqeLqNX5zM4M8yUx0kSKA2BgCaJFvdWj9b5j8X7sq229wm6dB7M4ueMLfaXJWakoRJP+bEnTat+3yIr6m8vO1qfpRW8ZHnRtObcQejDQDNjQxVMc9ST7FBWsSLPnwoUpRJhrzib2XB8VS6otZ/GpmE7SBdc3KrtXi/MgczT3Q9WW45z7vfrzsT219zh06NH/+rzA2bJibEPgmLQftwVCID9898LmsTfmSos5dohRDpfBpbYrPGPuiRSEbuxxNGnZ9UhbIPrHvCj+jxOHP3Z68a89Z5c1O+wGn91+bFDnm11KVDUk5CEW18k8ZDFLaeo2qQHYOcpqUHeOLUuaOuDjPbvbAp7lYiO0bPZi6h9z447PBrWFMEQObXO13+yv1f1svUwnumUtEb2FCKPZf3MhVRXH1sctkeIuSxnVBscV1Xsj0BnmbdY+KSj3Vqeg24nuyc0LML2i6wTleow== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "+9NkmQZUWidGVFdel/s8bjQtVgthWEILEX2DtAZST5c"
    );
}

#[test]
fn parse_rsa3072_publickey() {
    let ssh_pubkey = PublicKey::from_string("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsMWlhNHSxLoilw8hFlR/uo0Qrq0xNEO4jxsAyxnbxCckxmGPURR5t2KyUS0H7kGoCoG5+8O4dmNztTy3GPBXC+snFpbhtCAUvPo3uEVm/VHXEhXxOG0s6RjAZ2vBGED5Ahx63EYRfDeYr5bzuJqzfw4ELCFElrch3V+YWMgzeF0WYVYrrS9lHrzPOE0r9tJaFZ6yPxVRj/OCiHXnY+gElU1xUjmeACfir4z1HyvDi3C3vcMKl15ARDLzhAB4TnnIy2I5CgEVage5nySM7lttejvMjwBOvAio1YZO8F460IO7Uyk3Y6BEO+qIbtuN1vvXvOhkHN/JZZFCTOQDHSRwuc9OlsKxCFgf/XndxHTVSlhlEaWFGXzD8HS6xwiQ24M5c4DOnrxGLrUVxjU17736PAmW6L2Wsy3C+/6ns4K+lOO1IS5V4Fadtf5FGblSAU/8apH2EO+0KkdqI+2C4mIqyu1oHTfQBJ6rA/4JZTPAdh26YA+8L5ZANWkeshON3THU= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "YlmcNWmmzkuy/5oIlCoqyd5JkIaa/RgzjlF7nFzsZ3o"
    );
}

#[test]
fn parse_rsa2048_publickey() {
    let in_data = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDfqT0yXZzoHYrTDBrvFbjrjOVQ9wDOL6PEmEToPVrNavjXOAfmZDLd6azKYDifveVXjBUV+Rum7cz5MXHBh046NxfG4g6OVmVQxF+czWP0Oly3L4Vwx3Q4mbD3shTLF36Yv3Ehb6DzGj/SDvCFgTjYqzkuupN7KKrk4DUxTbCvgoA7W0SIGYD7frIw64Kxp1Mb7AAyh5z0WSzYyl15lRVGnEBRb5BEEMQO8cvkmUEUvl0jALY+hawejjedzWjXiQd/xO4E8FfKNuIe0SUTHZM0DbeBvWbsef5PI1/Hw3TCtFXEOBsMYTQwSbDGiFEDqNQ+97dhctKyueoFdfbodkF obelisk@exclave.lan";
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "A7S6yWfLWgKphtN5UzBbKbhSE71bK/NB6x6NE0DJOpU"
    );

    let out_data = format!("{}", ssh_pubkey);
    assert_eq!(in_data, out_data);
}

#[test]
fn parse_rsa_sha2_512_8192_bit_publickey() {
    let in_data = include_str!("keys/public/rsa-sha2-512-8192.pub");
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "TL9DbJ2yKuM/NV1gbE8Y9XRiu56wzhdcXBJyw8mMOfs"
    );

    // We cannot run this check because the re-encoding will change the name
    // back to ssh-rsa, making it not the same. While we could choose not to do
    // this, this is what ssh-keygen reports so to maintain compatibility with
    // it, we do it as well.

    //let out_data = format!("{}", ssh_pubkey);
    //assert_eq!(in_data, out_data);
}

#[test]
fn parse_rsa_sha2_256_4096_bit_publickey() {
    let in_data = include_str!("keys/public/rsa-sha2-256-4096.pub");
    let ssh_pubkey = PublicKey::from_string(in_data);
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(
        ssh_pubkey.fingerprint().hash,
        "sqSMm4+0OSx6UlrEUW7Khu40yymOGt9nkF2U2/ixHKQ"
    );

    // We cannot run this check because the re-encoding will change the name
    // back to ssh-rsa, making it not the same. While we could choose not to do
    // this, this is what ssh-keygen reports so to maintain compatibility with
    // it, we do it as well.

    //let out_data = format!("{}", ssh_pubkey);
    //assert_eq!(in_data, out_data);
}
