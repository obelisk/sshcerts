use sshcerts::ssh::AllowedSigner;

#[test]
fn parse_good_allowed_signer() {
    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    println!("{:?}", allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(
        allowed_signer.key.fingerprint().to_string(),
        "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M",
    );
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string()],
    );
    assert!(!allowed_signer.cert_authority);
    assert!(allowed_signer.namespaces.is_none());
    assert!(allowed_signer.valid_after.is_none());
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_quoted_principals() {
    let allowed_signer =
        "\"mitchell@confurious.io,mitchell\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    println!("{:?}", allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(
        allowed_signer.key.fingerprint().to_string(),
        "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M",
    );
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchell".to_string()],
    );
    assert!(!allowed_signer.cert_authority);
    assert!(allowed_signer.namespaces.is_none());
    assert!(allowed_signer.valid_after.is_none());
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_options() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority namespaces=\"thanh,mitchell\" valid-before=\"123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    println!("{:?}", allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(allowed_signer.key.fingerprint().to_string(), "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signer.cert_authority);
    assert_eq!(
        allowed_signer.namespaces, 
        Some(vec!["thanh".to_string(), "mitchell".to_string()])
    );
    assert!(allowed_signer.valid_after.is_none());
    assert_eq!(allowed_signer.valid_before, Some(123u64));
}

#[test]
fn parse_good_allowed_signer_with_consecutive_spaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io    cert-authority    namespaces=\"thanh,#mitchell\" valid-before=\"123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5  ";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(allowed_signer.key.fingerprint().to_string(), "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signer.cert_authority);
    assert_eq!(
        allowed_signer.namespaces, 
        Some(vec!["thanh".to_string(), "#mitchell".to_string()])
    );
    assert!(allowed_signer.valid_after.is_none());
    assert_eq!(allowed_signer.valid_before, Some(123u64));
}

#[test]
fn parse_good_allowed_signer_with_empty_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority namespaces=\"thanh,,mitchell\" valid-before=\"123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(allowed_signer.key.fingerprint().to_string(), "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signer.cert_authority);
    assert_eq!(
        allowed_signer.namespaces, 
        Some(vec!["thanh".to_string(), "mitchell".to_string()])
    );
    assert!(allowed_signer.valid_after.is_none());
    assert_eq!(allowed_signer.valid_before, Some(123u64));
}

#[test]
fn parse_good_allowed_signer_with_space_in_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority namespaces=\"thanh,mitchell   tech\" valid-before=\"123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(allowed_signer.key.fingerprint().to_string(), "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signer.cert_authority);
    assert_eq!(
        allowed_signer.namespaces, 
        Some(vec!["thanh".to_string(), "mitchell   tech".to_string()])
    );
    assert!(allowed_signer.valid_after.is_none());
    assert_eq!(allowed_signer.valid_before, Some(123u64));
}

#[test]
fn parse_good_allowed_signer_with_unquoted_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority namespaces=thanh,mitchell valid-before=\"123\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_ok());
    let allowed_signer = allowed_signer.unwrap();
    assert_eq!(allowed_signer.key.fingerprint().to_string(), "SHA256:QAtqtvvCePelMMUNPP7madH2zNa1ATxX1nt9L/0C5+M");
    assert_eq!(
        allowed_signer.principals,
        vec!["mitchell@confurious.io".to_string(), "mitchel2@confurious.io".to_string()],
    );
    assert!(allowed_signer.cert_authority);
    assert_eq!(
        allowed_signer.namespaces, 
        Some(vec!["thanh".to_string(), "mitchell".to_string()])
    );
    assert!(allowed_signer.valid_after.is_none());
    assert_eq!(allowed_signer.valid_before, Some(123u64));
}

#[test]
fn parse_bad_allowed_signer_with_wrong_key_type() {
    let allowed_signer =
        "mitchell@confurious.io ecdsa-sha2-nistp384 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_invalid_option() {
    let allowed_signer =
        "mitchell@confurious.io option=test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_invalid_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io namespaces=a\"test\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io namespaces=\"tester,thanh\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_invalid_principals() {
    let allowed_signer =
        "mitchell@confurious.io ,thanh@timweri.me option=test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_empty_principal() {
    let allowed_signer =
        "mitchell@confurious.io,,thanh@timweri.me option=test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_timestamp_option() {
    let allowed_signer =
        "mitchell@confurious.io valid-before=-143 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_conflicting_timestamps() {
    let allowed_signer =
        "mitchell@confurious.io valid-before=143 valid-after=145 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_duplicate_option() {
    let allowed_signer =
        "mitchell@confurious.io namespaces=thanh namespaces=mitchell ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn parse_bad_allowed_signer_with_quoted_key() {
    let allowed_signer =
        "mitchell@confurious.io \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5\"";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 \"AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5\"";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}
