use sshcerts::ssh::Certificate;

#[test]
fn parse_ed25519_key_signed_by_ed25519_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIK8bQbhlLJcUXYHcTA2FkU6qDvY4f9IXO3PMBMT",
        "zR76hAAAAIB7fwcuszYuMUHSRn/Jgx0R5o8440VO5fuRzFwz6gBpv/v7+/v7+/v4AAAABAAAAD29iZWxpc2tAZXhjbGF2ZQAAABcAAAAHb2JlbGlzawAAAAhtaXR",
        "jaGVsbAAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZ",
        "wZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACB",
        "F8fjQjhPiIQoIpSZUQJCrjBCqLOanQPT9T2VDzoYySAAAAFMAAAALc3NoLWVkMjU1MTkAAABAQQtSUBHzgzLEYLcuYmtZlVz2guW9141tmzSjWnDKrPv07r2W0BB",
        "cMvF5LlgHwzQN3iY4gfCrfaUF6UW58P/ADg== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_ed25519_ca_bitflip_should_fail() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIK8bQbhlLJcUXYHcTA2FkU6qDvY4f9IXO3PMBMT",
        "zR76hAAAAIB7fwcuszYuMUHSRn/Jgx0R5o8440VO5fuRzFwz6gBpv/v7+/v7+/v4AAAABAAAAD29iZWxpc2tAZXhjbGF2ZQAAABcAAAAHb2JlbGlzawAAAAhtaXR",
        "jaGVsbAAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZ",
        "wZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACB",
        "F8fjQjhpiIQoIpSZUQJCrjBCqLOanQPT9T2VDzoYySAAAAFMAAAALc3NoLWVkMjU1MTkAAABAQQtSUBHzgzLEYLcuYmtZlVz2guW9141tmzSjWnDKrPv07r2W0BB",
        "cMvF5LlgHwzQN3iY4gfCrfaUF6UW58P/ADg== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
    let e = cert.unwrap_err();
    let e = format!("{}", e);
    assert_eq!(e, String::from("Certificate is improperly signed"));
}

#[test]
fn parse_ed25519_key_signed_by_ecdsa384_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHHmkeWvEeC/3nPYsqHnltaMNJ00AENJUK8v5L8",
        "2E7McAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAIg",
        "AAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEQrr/bABwA6XZ1nNonmfUl2AKAmREmMZ/ZNYxYm+ZoIMehdcEkkOJLde+10reVEqPTK76eg6",
        "PFmuXSFYBCv/bxanUtLSBW6M3DnnsiSE2lRI3S0exah/yoE6Md6/Mux8gAAAAhAAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAAaQAAADEAubZwtO0CnWBrNJ0ZD+8",
        "7ueqG601uT98WW0txBBoVYE2dMkaZ2aAwytE1bCUjZgsNAAAAMCgA3Q6OXDE4F5H1OX9ZthBP+V30l1HyN8oFzJ/rdr38UtxYNI581FcANSp+tT0VYw== obelis",
        "k@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_ecdsa256_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIJ5o2IAdz9VtWeIKiI+u7gHDfDSBWfiSdSaeLug",
        "FNoeGAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAGg",
        "AAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEESaQHrC2+ReSe4xFAC7x5ztZy8jOd5KdxvY0C4x7FyjjAuIR6XE1mLYS+a5Rk1fD4M8vK5JH",
        "K7CtBYu2aOlQTzAAAAGQAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEkAAAAhAL+PhSGcl7X8KD3JNJAfg/sNylohVp7oiItFKG53qUdrAAAAIGAsjsBosbZKZTa",
        "rw9qobaP7N2BQntp8amG9NCLzE3Fp obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_ecdsa384_ca_bitflip_should_fail() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHHmkeWvEeC/3nPYsqHnltaMNJ00AENJUK8v5L8",
        "2E7McAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAIg",
        "AAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEQrr/bABwA6XZ1nNonmfUl2AKAmREmMZ/ZNYxYm+ZoIMehdcEkkOJLde+10reVEqPTK76eg6",
        "PFmuXSFYBCv/bxanUtLSBW6M3DnnsiSE2lRI3S0exah/yoE6Md6/Mux8gAAAAhAAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAAaQAAADEAubZwtO0CnWBrNJ0ZD+8",
        "7ueqG621uT98WW0txBBoVYE2dMkaZ2aAwytE1bCUjZgsNAAAAMCgA3Q6OXDE4F5H1OX9ZthBP+V30l1HyN8oFzJ/rdr38UtxYNI581FcANSp+tT0VYw== obelis",
        "k@exclave.lan");

        let cert = Certificate::from_string(cert);
        assert!(cert.is_err());
        let e = cert.unwrap_err();
        let e = format!("{}", e);
        assert_eq!(e, String::from("Certificate is improperly signed"));
}

#[test]
fn parse_ed25519_key_signed_by_rsa8192_ca() {
    // Test max size RSA Key
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIOLeWQayd9EHsOqPDSUCmooLY1RcZOIjjDj9zMy",
        "UoYqBAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAABBc",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAQBAOZf9y86lW+ac+Ng5mWAZw+gCQDkabWxhJ9pY6kvTU+uNEkq/02nl1djh15oI/D/v/m3RMVdMt9MxrKRIW2Nd2LOLDj87ZN",
        "yL7jvvHFscsoFrq/bIAVhAVCKErksv0Hy8XFYTDkT/L2DHC0k9AHnDiH/FSukcoCzXVUUQG3Hhm+AuWCKTTz1a7XOykp7cj6/jC5C/+2g7QtH2+dOsNvWnimWkbn",
        "RNsGAXjcZTHeUkAjT9Cb1OMy4vHmYoXXqPX5c/Wn9cZbPES1F+9hxrIBs8dEfszpXpxVN6x8y0aE5HGL2hFZWkTPwOrj2GJqikFCOam0p5RprzXKGkDtJ3SS5DyZ",
        "MjwoYT9jk7vrfejQ2yHVXryF7tKZImOEi79QL91hiXv5vLBpa/7KUqkyXTKbWlASUNfTyVM9AP5xb/rTvJSAlWwO8Nvzf/HGUF+v8Vo+YWlLCrs0QBujVexErbnf",
        "Erhdp8h4WDovO+5owU3vfDbz2SZz11yMjBVFlk8T8IcpVLv6iFpW+4BKLhCBA1UPktW3pnwYv5ueYKQDCaQdoRYDjoIJj5ksNguOPNBqLQwZTVSVb7K7Zcg9u48/",
        "HCfsA1CRWCvdtDdE+yekDUHDMf8KmFfLqQ5x/yaztEodp+HsTaTtIj5Gu0C2BFWxZ9k6I9brGCIG9C1Kd2EAtgM2r3Rwvuo4OrVowv43stsgLlXCQr7hSQMaMlDJ",
        "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 obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_rsa5000_ca() {
    // Test a nonstandard size RSA Key
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIASmJai1htqJueveQ15LesBgJthMq4pPEgfY+q",
        "lC09SAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAog",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAJyANs3mu4ORAF2nM95IEWoL/JBLlJKJF/PUb9ZGc99KctUkVlXx5tUUbubzSyjCLimagdVFE/uzewzNu8NXFO0kub1GivKbtG",
        "mI73KgAQB/AAndOUPCp/PTFXhpwDTgKkpSuczy55wlbR5VnuHMBiB1aUldyim5085ukE+ocrbDj3qMj5WQZANyVlYcw/3Hziaqbcw1C8LuuN6XQeG93zvySxSb+k",
        "kW2S8Ljfut+7S+rUFQ7C46PyFVQ9oOxJiejdO/xD/lbmOFJLVpi/81Ng5+h70YtxLOXpOo72BKTTXeUqKoEXy9PJcrxMOFfdUNLKW57qCCxe4lZyNFz1ECiA9sto",
        "G/brzq7ckt9ewbuGukMNLFJpPwURlgmIzLn3e4ap7EueoAEVpy6EL7HrBSz22EAa1WpEVmVtwU+w6w4RKo3CMsJB466FrXlpCJSt3knEb1deRafhInG5m810caL3",
        "Sw9rJjRxRLR9lqQLFpffB4pCryqmx2/5O+XcD4GDW5xD8ARX3hMINgnl6DwoGArYRdyfINxlRJgng6qY+yB5OkRZcUzpn6tiPWJo60Kin2RkW7J69jAX5//67tWX",
        "CZyWZTf7gBeHMdG7VRpAAgaWUiDUVByAeOpyq8tfEvZTJOYOhM9tJVDYzbDOubkwECYgJgpd+Un3LOgUvfVrWGzNppzMcljmtpWie6to8CWSwqtALynIzZ6z7rQX",
        "+/jGx1tVLtPVDffumL+3+F/GSP/hk978GMjkRFsjRLAle6AZ787cEKRTah72TfOrADN58eYKXY/8QUYTeJ+pEbcmYxkm3lEXFzd/FLUUAuf+fB3Gwj1hllssAAAK",
        "FAAAADHJzYS1zaGEyLTUxMgAAAnEhgBgHCYG/RSNxPH5+6L4Gq6GJfAqTfO/CojV3OIdsT8nvSGON5DvzofxXWC+j++ULQJ5zw3pBZuxzp2wZRduuWpTvV+puR/y",
        "KakcdMEj6F3KLUG0u3mtNebCTuPePwVe5nMNdfWUUTau0UoyhVeq0Ld24w4Jf1c+Hrz4Y0/4qIOt3e4spDnGnEgHXVYJI4RSU+Mfs+mm9MGx55QFGOK2dzEd0QAo",
        "z/ghTOxwJeyVAm3XEVVh8JHHiIt2Xh+zVcwjkMXJsB1VyIFbCRH1XJYk9f8qfMDuULslGXF7TbOFtoDexQiVo3lir+pCUDfcvIol9+uqPePiMw9O43dAFWEPFJXQ",
        "xndngZ80opfmrTwq/NT/kwbSXheGRWNcQBUSJFQhhzy5fvXXSGDrzDLuWhqZF6Hg3I1kH4PxrL8ea/AP1yLTZAb60bAKJJUlpqJv/TRUAST7xRD3VNPZnjimM0EX",
        "qDh6sHyTG2zM7C6pOAevN2uzWcB9wNeJ3umasg8245KWXOPzq0dq8Adnr34Exk0OcsR2oY0fwc0izvd3WoXxIt4llastqnS/uEC0qkbVeQ1E0OagUX7frvKyRNUt",
        "yROxykfw0RsvISJpK91ALXGnZx+cJq1pA0p8RzAKL2/1V+cnXuILdHhVU4DzKDXeXIHV69xxkOPX4GzKhBHJU2K1d4BL1xornXjQRmyQU3j7N+0uMNmGDYayL0tr",
        "VBqhMb8MgvT/5J/RPDLlp65IEDx9Y15ykHIj2pfi9GqBoGtAqDrsuJKQQwPDfYiq1u+QYYGULRzso/xo+P0OK64WEK687fjDdov8Jl8Wezu8EkFfXH7YL obelis",
        "k@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}


#[test]
fn parse_ed25519_key_signed_by_rsa4096_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGjRbDdbgZV4cydKA/VghCFnBVAXdt4y1ld3W/O",
        "Vau88AAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAhc",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAIBALORmW4cJ+9pyNEP7qNf9gtOnqRTV/SwynGlI9EpvmWXSG9IdVgmiMNfWENu7xnYHHqijP7slp5radcXjUSxmYnx7waDNUv",
        "PlpOQKNZlMW7KRfPvUd2CyPuop3gHlK6Ow9c15F/bdRF8bmRJhIVYbha1hQYurOUudc6n9o3i//1u0p3sG1nvnCL7rm9CjyhHVRVs/n0fhI15CajA/y32aVzScll",
        "A1mDR7dITGVPjAPQRhXmQXbegVURYrePe4HFcOcoP9BWR+0bclVUuyFwPcVDz+loTE7ZTO1sVGNqhmabtude9VBJ2uxn5aFaVKGuFgbsy4Vm3DQKpKq4cegP+lUN",
        "SdruqDYYv/wvs0Sta2BmpY36JJgN/n5cRXBKS5nbPcQoe3nGSl+gZ2HvkJdaj6iF5OPN7CLC6ATy2Ug5ms4i7mtih2rpuPjI+8fddr8kicISfr12k2EjoiGLVvJ1",
        "hj4iPym7H6r8LVugsxUXZ3MpI+veWE/zhE9QaQ36SgXiEt8q/T4kb6+JVxNUSwMZciTI8NQXKPM/r/Y1W15FCbgGRXFYHl9afPgpAslq8x9+RWAs9BsMgffSbikG",
        "0LXLn6Ehuiw70gFlafVkpXXSqR8+2o6fLleueLHrGX68jxbk3xJvQ30umgQRucqrFbL8QzRlVEKEv3KVRQIQug60q/VcnAAACFAAAAAxyc2Etc2hhMi01MTIAAAI",
        "AVB6zjdL9C7NsewtAzW0KbXtlUUSmAEeJIOMwCQ4dYuYoDIytAos1NAAo6yJWiZhC4ZPrVnFm0nDVCBsmTlA3FWtntV9+lzL8PxkxJu0TCUiumZ2YcCf3T+7oStJ",
        "lZUOKJ7B5vCjAp/3ERxg0pQ20sNqPQ8Smt7XZSj252ZRm+27L7QhEL+QL0bgNU9/yaQaoiQeG3D3+XEjwS05nMV3R8F+kQVxF8SD+ZDgax/28uMNbFcIlzGnUHKF",
        "oKK97u85K//4Xhogq1Ru3tFQ79/eg4a39bm7whYtSsouIXTB/bysC3SE6/sd2Q5VT2INJc2HheQAB1BukUW779QWTaymfcCf5MOSVfPLHvCO726Xmx+DinkcCVna",
        "NpI0PPvkqzl923MJGRkvSD1pdw1i2I9YPN59uE3IRvcV1iLnBkxpILT1XKFrzFP4WoAzM1YONEFf1KQgf3x1It4V9Zjdtkn/2QtxDl8OC85MT+9ALX2hFF+f0dFq",
        "YLRGPDRjWsmx7gmxeER3yPDTnGMUBc8MKk2YYvFm0OJthOJ/4wJYD/wiVd1qc9OMtNvsE9VyZl4XX/bla1a966AxEfj2Yi8ys/vKulGYNj9ZNZq7AbUPY3JVUe8S",
        "ZEoT9DPYURpKo5HRIZWA4qPh1IEX0K3SpNBKcITvxLIIWInnZ3mafRh4xX+c3auI= obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_rsa3072_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGXyfki2rThO79Zt63vfCDK4pYYhRQJkEajArhR",
        "DB84YAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZc",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAGBALGWlUr9LI2o/gbuhaK3P1JuaarQ2h4/2W1VgWNZG91yGYXQXmH/kR4fNjPJ0eHfmMftOezcqj60VQ9k69rI8CiOK1j6KPP",
        "hxglUwwdtFkL4v9g1rs592rnPT/zlwW87J7n0G1iiqhQTyeT/+3uQI+eaKPBG6rcRJTT8U8du83ksCdiiG+SB9DZQOMeJy+s5W8+5mJdoMs0IYUdTMr6FyMT7Kq+",
        "4Ow4OlRyUlGSA0/rEgtL8mcQOxjZpnmUghevj8tNKsHnAuX8ImVT0QFO1Bvu61+PjShHpV4KVgmqMvazwROvefh2wPA7P9kNilQGYe0AjaFaMDuz+cjRKOAh0yhO",
        "5djLutj/LumQCYRe+rf6subTSQXYHza35bkeT/OEP3mrc5Hz2Wv7oWxZ1j25YlHrny1+jPzJLp2AJXFjl+KNt3je4qP9fnLHgvoT0Ikn7hhKfQPGaPUlXk7FFoKw",
        "3jdHYtC9kkgOKjB5/pzaDlBfGaYpKCrVDrl3FHZ5PZIRELQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgKldhxxqTruCZUhXzb1bWjamXkGRCVm2QURpJq2GpJXSAq5",
        "cxJ1948sV2J6jUd93qybHQfftoHjj/kVub/0JY3ohy3zy5NwhE2cgDZVBi3gNZADuZE24RzptTXhpa8hnul1aeMQLoOfQ0w00lksTxETePFm7NzPlwGzKDQ5RsdK",
        "x/27RhhTsxUktSHeylgil/ONEQpypqZgsHH2tma52GkF4IfZVuzFo+O0L0pLhgBlgnar4PT3G0X5kPISnN9afMqixcn/qjb8hNO0rAsdUg1ehf1Fasm4bkR5L7KU",
        "WGK0Wb+kN2dctxuRR72lEj6GaRU3fcEsXqeJh97alSJDQSadXFIaVWw/DvBOJQ10JS4OqfBzsN7bM2ShxN1NuATIdf1g5DGai42Ijg2JS+YuWOzF+SighZhaDGJS",
        "9Z9QEixQA38UvnEuEUtEb8v02coefoY45Jtu+wm0zp6BXBT4o8acBFht7mhr/YPB5TModWpCn8SLmaEjaoFcPFnZOzN+R1g== obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_rsa2048_ca() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFF+64vXOUBsdUN+p5kuWxTcCAY5RBMUopsRmpG",
        "nYDPaAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARc",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMBT6wBeWHcupape+08+VVeI+bK6ttSXoun5QaMZpgEqHdke5RiiegYlWxxgQ0ndIai+2HOkdNhYP/2kOjBHWdeEj8ExSCj",
        "F1+x16KNcuzZ7fY1g1TK7TV7sSo2U/N4CLYkfjLU5QQx6xbL0yfUQ/PB2Xl63hlBCKD31qzozcfWjSi0LqwR/+nlrBsEb1d6nHtfd3qo9Otz7R+zzwLIcbCEJsf8",
        "eXcR33SDMWO5U5cJAL4koICFsmamNdJwJiMr//4lyOOZiCUFeWk+90KTPYFUDWMrCzDj9+3EH6IYB5LZrnLFVb6cKZprsYgjzn+lQmQsT8QzXd3Ao0se1Hmin/Dc",
        "AAAEUAAAADHJzYS1zaGEyLTUxMgAAAQAUxzj1aMRxxfIU9qR+sCn/0NLwyCYDTXKUSYWZqYGJq1PbPIxGD3QsDLDpzJ27Laqj77gYh/JaevF9ERH4F7ABfKcfemM",
        "DT1aPyDPwl6389+GjtQuTNuiosqKo7IaG2zBhCugO69CZV/tt5taG3WI2T3/0rCFzGVFPk5KUzJBMsXGN0FM1pbpL9oKYpeEz0qiW9GwhtjSSgBr/oTY/VkLoUW1",
        "KtUQwaPl8JWIOEt1dark8J+dDTkatPsjuBfRuXPGVdlwg7rvi45ZQchZqMZdFf7Cip/6OWoeisLbYlJO1BqMCIFLbKNbHv9UCrtiWOU//+nYPIzWdoy5vbK73wQV",
        "q obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_ok());
}

#[test]
fn parse_ed25519_key_signed_by_rsa2048_ca_bitflip_should_fail() {
    let cert = concat!(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFF+64vXOUBsdUN+p5kuWxTcCAY5RBMUopsRmpG",
        "nYDPaAAAAIAzeM5AMDRMvFq3N3CutxplLNvNlaoCppOicyQN4cMGp/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
        "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
        "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARc",
        "AAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMBT6wBeWHcupape+08+VVeI+bK6ttSXoun5QaMZpgEqHdke5RiiegYlWxxgQ0ndIai+2HOkdNhYP/2kOjBHWdeEj8ExSCj",
        "F1+x16KNcuzZ7fY1g1TK7TV7sSo2U/N4CLYkfjLU5QQx6xbL0yfUQ/PB2Xl63hlBCKD31qzozcfWjSi0LqwR/+nlrBsEb1d6nHtfd3qo9Otz7R+zzwLIcbCEJsf8",
        "eXcR33SDMWO5U5cJAL4koICFsmamNdJwJiMr//4lYOOZiCUFeWk+90KTPYFUDWMrCzDj9+3EH6IYB5LZrnLFVb6cKZprsYgjzn+lQmQsT8QzXd3Ao0se1Hmin/Dc",
        "AAAEUAAAADHJzYS1zaGEyLTUxMgAAAQAUxzj1aMRxxfIU9qR+sCn/0NLwyCYDTXKUSYWZqYGJq1PbPIxGD3QsDLDpzJ27Laqj77gYh/JaevF9ERH4F7ABfKcfemM",
        "DT1aPyDPwl6389+GjtQuTNuiosqKo7IaG2zBhCugO69CZV/tt5taG3WI2T3/0rCFzGVFPk5KUzJBMsXGN0FM1pbpL9oKYpeEz0qiW9GwhtjSSgBr/oTY/VkLoUW1",
        "KtUQwaPl8JWIOEt1dark8J+dDTkatPsjuBfRuXPGVdlwg7rvi45ZQchZqMZdFf7Cip/6OWoeisLbYlJO1BqMCIFLbKNbHv9UCrtiWOU//+nYPIzWdoy5vbK73wQV",
        "q obelisk@exclave.lan");

    let cert = Certificate::from_string(cert);
    assert!(cert.is_err());
    let e = cert.unwrap_err();
    let e = format!("{}", e);
    assert_eq!(e, String::from("Certificate is improperly signed"));
}