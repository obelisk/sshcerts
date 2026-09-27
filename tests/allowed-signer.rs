use sshcerts::error::Error;
use sshcerts::ssh::{AllowedSigner, AllowedSignerParsingError};

#[test]
fn parse_good_allowed_signer() {
    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
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
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,mitchell\",valid-before=\"20240505Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert_eq!(allowed_signer.valid_before, Some(1714867200i64));
}

#[test]
fn parse_good_allowed_signer_with_utc_timestamp() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,mitchell\",valid-after=20240505Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert_eq!(allowed_signer.valid_after, Some(1714867200));
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_hm_timestamp() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,mitchell\",valid-after=202405050102Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert_eq!(allowed_signer.valid_after, Some(1714870920i64));
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_hms_timestamp() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,mitchell\",valid-after=20240505010230Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert_eq!(allowed_signer.valid_after, Some(1714870950i64));
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_consecutive_spaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io    cert-authority,namespaces=\"thanh,#mitchell\",valid-before=\"20240505Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5  ";
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
    assert_eq!(allowed_signer.valid_before, Some(1714867200i64));
}

#[test]
fn parse_good_allowed_signer_with_empty_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,,mitchell\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_good_allowed_signer_with_space_in_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io,mitchel2@confurious.io cert-authority,namespaces=\"thanh,mitchell   tech\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
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
    assert!(allowed_signer.valid_before.is_none());
}

#[test]
fn parse_bad_allowed_signer_with_unquoted_namespaces() {
    // Options are comma-separated, so the parser reads an unquoted list as namespaces=thanh plus an option named mitchell
    let allowed_signer =
        "mitchell@confurious.io cert-authority,namespaces=thanh,mitchell ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(
        matches!(
            allowed_signer,
            Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(ref v))) if v == "mitchell",
        )
    );
}

#[test]
fn parse_bad_allowed_signer_with_space_separated_options() {
    let allowed_signer =
        "mitchell@confurious.io cert-authority namespaces=\"thanh\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    // Like OpenSSH, the options field ends at the space, so the parser reads namespaces=... as the key type
    assert!(matches!(allowed_signer, Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidKey))));
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
        "mitchell@confurious.io valid-before=20240505,valid-after=20240505 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
    assert!(matches!(allowed_signer, Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamps))));
}

#[test]
fn parse_bad_allowed_signer_with_duplicate_option() {
    let allowed_signer =
        "mitchell@confurious.io namespaces=thanh,namespaces=mitchell ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
    assert!(
        matches!(
            allowed_signer,
            Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions(_))),
        )
    );
}

#[test]
fn parse_bad_allowed_signer_with_quoted_key() {
    let allowed_signer =
        "mitchell@confurious.io \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
    assert!(
        matches!(
            allowed_signer,
            Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidKey)),
        )
    );

    let allowed_signer =
        "mitchell@confurious.io \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5\"";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
    assert!(
        matches!(
            allowed_signer,
            Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes)),
        )
    );

    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 \"AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5\"";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
    assert!(
        matches!(
            allowed_signer,
            Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes)),
        )
    );
}

#[test]
fn parse_bad_allowed_signer_with_invalid_timestamp() {
    let allowed_signer =
        "mitchell@confurious.io valid-before=1941 \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io valid-before=\"1941\" \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io valid-before=19411293 \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io valid-before=1941293 \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());

    let allowed_signer =
        "mitchell@confurious.io valid-before=19411293Z \"ssh-ed25519\" AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer);
    assert!(allowed_signer.is_err());
}

#[test]
fn display_allowed_signer_round_trips() {
    let allowed_signer =
        "mitchell@confurious.io cert-authority,namespaces=\"git,file\",valid-after=20240101Z,valid-before=\"20240505123045Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let allowed_signer = AllowedSigner::from_string(allowed_signer).unwrap();
    let formatted = allowed_signer.to_string();
    assert_eq!(
        formatted,
        "mitchell@confurious.io cert-authority,namespaces=\"git,file\",valid-after=\"20240101000000Z\",valid-before=\"20240505123045Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
    );
    assert_eq!(AllowedSigner::from_string(&formatted).unwrap(), allowed_signer);
}

#[test]
fn display_allowed_signer_quotes_principals() {
    for principals in ["\"mitchell confurious\"", "\"mitchell#confurious,thanh\""] {
        let allowed_signer = format!("{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5", principals);
        let allowed_signer = AllowedSigner::from_string(&allowed_signer).unwrap();
        let formatted = allowed_signer.to_string();
        assert!(formatted.starts_with(principals));
        assert_eq!(AllowedSigner::from_string(&formatted).unwrap(), allowed_signer);
    }
}

#[test]
fn display_allowed_signer_clamps_timestamps() {
    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let mut allowed_signer = AllowedSigner::from_string(allowed_signer).unwrap();
    allowed_signer.valid_after = Some(i64::MIN);
    allowed_signer.valid_before = Some(i64::MAX);
    assert_eq!(
        allowed_signer.to_string(),
        "mitchell@confurious.io valid-after=\"19700101000001Z\",valid-before=\"99991231235959Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
    );
}

#[test]
fn display_allowed_signer_escapes_quotes_in_namespaces() {
    let allowed_signer =
        "mitchell@confurious.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";
    let mut allowed_signer = AllowedSigner::from_string(allowed_signer).unwrap();
    allowed_signer.namespaces = Some(vec!["git".to_string(), "a\"b".to_string()]);
    assert_eq!(
        allowed_signer.to_string(),
        "mitchell@confurious.io namespaces=\"git,a\\\"b\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
    );
}

#[test]
fn parse_good_allowed_signer_with_tabs() {
    let allowed_signer =
        "mitchell@confurious.io\tcert-authority,namespaces=\"git\"\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5\t";
    let allowed_signer = AllowedSigner::from_string(allowed_signer).unwrap();
    assert_eq!(allowed_signer.principals, vec!["mitchell@confurious.io".to_string()]);
    assert!(allowed_signer.cert_authority);
    assert_eq!(allowed_signer.namespaces, Some(vec!["git".to_string()]));
}

#[test]
fn parse_bad_allowed_signer_with_stray_quotes() {
    for allowed_signer in [
        "a\"b\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
        "a\"b c\"d ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
        "mitchell@confurious.io namespaces=\"\"a\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
        "mitchell@confurious.io namespaces=\"a\"b ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5",
    ] {
        let allowed_signer = AllowedSigner::from_string(allowed_signer);
        assert!(
            matches!(allowed_signer, Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))),
            "{:?}", allowed_signer,
        );
    }
}

#[test]
fn parse_bad_allowed_signer_reports_invalid_option() {
    for (options, expected) in [
        ("namespace=\"git\"", "namespace"),
        ("option=test", "option"),
        ("cert-authority=\"x\"", "cert-authority"),
        ("cert-authority,", "cert-authority,"),
        ("namespaces=\"git\",,cert-authority", "namespaces=\"git\",,cert-authority"),
    ] {
        let allowed_signer = format!("mitchell@confurious.io {} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5", options);
        let allowed_signer = AllowedSigner::from_string(&allowed_signer);
        assert!(
            matches!(
                allowed_signer,
                Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(ref v))) if v == expected,
            ),
            "{}: {:?}", options, allowed_signer,
        );
    }
}

#[test]
fn parse_good_allowed_signer_with_utc_suffix() {
    for timestamp in ["20240505UTC", "20240505utc", "20240505z", "\"20240505000000UTC\""] {
        let allowed_signer = format!("mitchell@confurious.io valid-after={} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5", timestamp);
        let allowed_signer = AllowedSigner::from_string(&allowed_signer).unwrap();
        assert_eq!(allowed_signer.valid_after, Some(1714867200i64), "{}", timestamp);
    }

    for timestamp in ["20240505ZZ", "20240505UTCZ", "2024050UTC"] {
        let allowed_signer = format!("mitchell@confurious.io valid-after={} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5", timestamp);
        assert!(AllowedSigner::from_string(&allowed_signer).is_err(), "{}", timestamp);
    }
}
