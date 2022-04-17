use sshcerts::ssh::Certificate;

#[test]
fn bad_signature_ecdsa_rs_length() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAP8",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs= key_id");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn bad_signature_ecdsa_length() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAP8AAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs= key_id");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn bad_signature_ecdsa_r_offbyone() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAgeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs= key_id");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn bad_signature_ecdsa_s_bad_length() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAAP8A8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs= key_id");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn modified_principal() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB2dyZWdvcnkAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs=");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn changed_pubkey_type() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs=");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn changed_pubkey_curve() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDM4NAAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs=");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
}

#[test]
fn actually_good() {
    let cert = concat!(
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgHWz37ZJkNhpEhC6pJkY",
        "cbKvPMgazcFt1hlgweWQVV/YAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uR",
        "Ufk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVP7+/v7+/v7+AAAAAQAAAAZrZXlfaWQAAAALAAAAB29iZWxpc2sAAAAAAAAAAAAAAABgKVzrAAA",
        "AAAAAAIIAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAABV",
        "wZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEPgO",
        "vv62WogLxC0i8XBvjd+KplMG1okf4IBC7zZvxpyCFbXQV8BgB38R1KbcoJcxhl5hXujr2HI1SDQ9tXCPLIwAAAGMAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEg",
        "AAAAfeKNwK3aNCzo32Ha1GF+dUV5j72XsBKY2E6kQQvFfPwAAACEA8kuD4M0umeh0zG7MXaZNHJk2tg+7e1T64Eu0+WdbShs=");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}
