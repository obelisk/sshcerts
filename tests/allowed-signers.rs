use sshcerts::ssh::AllowedSigners;

#[test]
fn parse_good_allowed_signers() {
    let allowed_signers = AllowedSigners::from_path("tests/allowed_signers/good_allowed_signers");
    assert!(allowed_signers.is_ok());
    let AllowedSigners(allowed_signers) = allowed_signers.unwrap();
    assert_eq!(allowed_signers.len(), 3);

    assert_eq!(
        allowed_signers[0].key.fingerprint().to_string(),
        "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M",
    );
    assert_eq!(
        allowed_signers[0].principals,
        vec!["mitchell@confurious.io".to_string()],
    );
    assert!(!allowed_signers[0].cert_authority);
    assert!(allowed_signers[0].namespaces.is_none());
    assert!(allowed_signers[0].valid_after.is_none());
    assert!(allowed_signers[0].valid_before.is_none());

    assert_eq!(
        allowed_signers[1].principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signers[1].cert_authority);
    assert_eq!(
        allowed_signers[1].namespaces, 
        Some(vec!["thanh".to_string(), "#mitchell".to_string()])
    );
    assert!(allowed_signers[1].valid_after.is_none());
    assert_eq!(allowed_signers[1].valid_before, Some(123u64));

    assert_eq!(
        allowed_signers[2].namespaces, 
        Some(vec![
            "thanh".to_string(),
            " ".to_string(),
            "mitchell mitchell".to_string(),
            " andrew   andrew".to_string(),
        ]),
    );
}
