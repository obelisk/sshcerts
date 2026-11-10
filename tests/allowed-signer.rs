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

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";

#[test]
fn parse_bad_allowed_signer() {
    use AllowedSignerParsingError::*;

    let key_data = KEY.strip_prefix("ssh-ed25519 ").unwrap();
    for (line, expected) in [
        // Blank lines and comments
        (String::new(), MissingPrincipals),
        (format!("# mitchell@confurious.io {KEY}"), MissingPrincipals),
        // Principals
        (format!("\"a b {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io,,thanh@timweri.me {KEY}"), InvalidPrincipals),
        // The principals field ends at whitespace or at the closing quote, and the rest is read as options
        (format!("mitchell@confurious.io ,thanh@timweri.me {KEY}"), InvalidOption("thanh@timweri.me".into())),
        (format!("a\"b c\"d {KEY}"), InvalidOption("d".into())),

        // Options: unknown names, and flags given a value
        (format!("mitchell@confurious.io option=test {KEY}"), InvalidOption("option".into())),
        (format!("mitchell@confurious.io octopus {KEY}"), InvalidOption("octopus".into())), // regress/sshsig.sh
        (format!("mitchell@confurious.io namespace=\"git\" {KEY}"), InvalidOption("namespace".into())),
        (format!("mitchell@confurious.io cert-authorityx {KEY}"), InvalidOption("cert-authorityx".into())),
        (format!("mitchell@confurious.io cert-authority=\"x\" {KEY}"), InvalidOption("cert-authority".into())),
        // A multibyte character where an option name ends
        (format!("mitchell@confurious.io namespaceé=\"git\" {KEY}"), InvalidOption("namespaceé".into())),
        (format!("mitchell@confurious.io cert-authority, {KEY}"), InvalidOption("cert-authority,".into())),
        // Options: values must be double-quoted, with nothing after the closing quote
        (format!("mitchell@confurious.io namespaces=thanh,mitchell {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=a\"test\" {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"a {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"tester,thanh\"\" {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"\"a\"\" {KEY}"), InvalidOption("namespaces".into())),
        (format!("mitchell@confurious.io namespaces=\"a\"b {KEY}"), InvalidOption("namespaces".into())),
        // Options: duplicates, and timestamps out of order
        (format!("mitchell@confurious.io namespaces=\"thanh\",namespaces=\"mitchell\" {KEY}"), DuplicateOptions("namespaces".into())),
        (format!("mitchell@confurious.io valid-before=\"20240505\",valid-after=\"20240505\" {KEY}"), InvalidTimestamps),
        // Options: the field ends at whitespace, so the next option is read as the key type
        (format!("mitchell@confurious.io cert-authority namespaces=\"thanh\" {KEY}"), InvalidKey),

        // Key
        (format!("mitchell@confurious.io ecdsa-sha2-nistp384 {key_data}"), InvalidKey),
        (format!("mitchell@confurious.io \"ssh-ed25519\" {key_data}"), InvalidKey),
        (format!("mitchell@confurious.io ssh-ed25519 \"{key_data}\""), InvalidKey),
        // A quoted key is read as an options field with no key after it
        (format!("mitchell@confurious.io \"{KEY}\""), MissingKey),
    ] {
        let actual = AllowedSigner::from_string(&line).unwrap_err();
        assert_eq!(format!("{:?}", actual), format!("{:?}", Error::InvalidAllowedSigner(expected)), "{}", line);
    }
}

// Cases from OpenSSH's regress/unittests/misc/test_convtime.c, plus case-insensitive suffixes and the epoch
#[test]
fn parse_allowed_signer_timestamps_like_openssh() {
    let parse = |timestamp: &str| {
        AllowedSigner::from_string(&format!("mitchell@confurious.io valid-after=\"{timestamp}\" {KEY}"))
            .map(|allowed_signer| allowed_signer.valid_after.unwrap())
    };

    // Local time, so the value depends on TZ
    for timestamp in ["20000101", "200001011223", "20000101122345"] {
        assert!(parse(timestamp).is_ok(), "{}", timestamp);
    }

    for (timestamp, expected) in [
        ("20000101Z", 946684800),
        ("200001011223Z", 946729380),
        ("20000101122345Z", 946729425),
        ("20000101UTC", 946684800),
        ("200001011223UTC", 946729380),
        ("20000101122345UTC", 946729425),
        ("20000101z", 946684800),
        ("20000101utc", 946684800),
    ] {
        assert_eq!(parse(timestamp).unwrap(), expected, "{}", timestamp);
    }

    for timestamp in [
        // Bad month
        "20001301", "20000001",
        // Incomplete
        "2", "2000", "20000", "200001", "2000010", "200001010", "2000010UTC",
        // Bad day, hour, minute, second
        "20000199", "200001019900", "200001010099", "20000101000099",
        // Invalid TZ specifier
        "20000101ZZ", "20000101PDT", "20000101U", "20000101UTCUTC", "20000101UTCZ",
        // OpenSSH 10.2 rejects the epoch and anything before it
        "0", "19700101Z", "19691231Z",
        // An escaped quote is part of the value
        "\\\"20000101Z\\\"",
    ] {
        assert!(
            matches!(
                parse(timestamp),
                Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(ref v))) if v == "valid-after",
            ),
            "{}", timestamp,
        );
    }
}
