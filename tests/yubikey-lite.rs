use sshcerts::yubikey::*;

const YUBIKEY_5CI_ATTESTATION: [u8; 630] = [
    0x30, 0x82, 0x02, 0x72, 0x30, 0x82, 0x01, 0x5a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x01,
    0xe6, 0x0f, 0x8c, 0x92, 0xd2, 0xe9, 0x07, 0xf6, 0xfb, 0x55, 0xd1, 0x31, 0x40, 0x0c, 0x9b, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x21,
    0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x59, 0x75, 0x62, 0x69, 0x63,
    0x6f, 0x20, 0x50, 0x49, 0x56, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x33, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x35, 0x32, 0x30, 0x34, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5a, 0x30, 0x25, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1a,
    0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x20, 0x50, 0x49, 0x56, 0x20, 0x41, 0x74, 0x74, 0x65,
    0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x39, 0x33, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62,
    0x00, 0x04, 0xa8, 0xce, 0x5f, 0x87, 0x68, 0xec, 0x28, 0xef, 0x51, 0x70, 0x09, 0x0e, 0xb8, 0x15,
    0xf5, 0x78, 0xb9, 0x20, 0x03, 0x2e, 0x12, 0x88, 0xe3, 0x52, 0xa0, 0xfd, 0xeb, 0xd0, 0x20, 0x08,
    0xbb, 0xf1, 0xed, 0x02, 0x78, 0x2d, 0x6b, 0x97, 0x78, 0x0f, 0x54, 0xb6, 0xce, 0x11, 0xc0, 0x17,
    0x57, 0x18, 0x5f, 0x57, 0xd6, 0xb4, 0xb8, 0x2b, 0x2b, 0x45, 0x49, 0xc2, 0x57, 0xc8, 0x52, 0xaa,
    0xc3, 0xdd, 0x60, 0x58, 0xda, 0x9a, 0x1d, 0x8c, 0x0d, 0x22, 0x48, 0x7c, 0xa9, 0x18, 0x80, 0xb5,
    0x8f, 0x18, 0xd6, 0x29, 0x5e, 0x6e, 0x62, 0xf0, 0xf4, 0x18, 0x76, 0x25, 0xa4, 0x86, 0x6c, 0x7b,
    0x16, 0xf0, 0xa3, 0x4e, 0x30, 0x4c, 0x30, 0x11, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
    0xc4, 0x0a, 0x03, 0x03, 0x04, 0x03, 0x05, 0x02, 0x04, 0x30, 0x14, 0x06, 0x0a, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03, 0x07, 0x04, 0x06, 0x02, 0x04, 0x00, 0xb3, 0xb7, 0xff, 0x30,
    0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03, 0x08, 0x04, 0x02, 0x01,
    0x03, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03, 0x09, 0x04,
    0x01, 0x05, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xb0, 0xb4, 0x97, 0x7d, 0xee, 0x7f, 0xc7, 0x59, 0x4f, 0x49,
    0x91, 0x39, 0xac, 0x6d, 0xdc, 0x3e, 0xca, 0x6c, 0x6b, 0x5b, 0x15, 0xb2, 0x24, 0x71, 0x9e, 0xd5,
    0xe0, 0x07, 0x96, 0x3b, 0xa8, 0x58, 0xa8, 0xe0, 0x77, 0x17, 0x5a, 0x22, 0x7a, 0x8a, 0x73, 0x43,
    0x80, 0xf3, 0xb3, 0xfb, 0x71, 0xef, 0x2f, 0x7e, 0xd2, 0x99, 0xe7, 0xa8, 0xa0, 0x38, 0xd6, 0xfe,
    0x21, 0x51, 0xa1, 0xe4, 0x28, 0x9c, 0x23, 0x13, 0x29, 0x86, 0x2c, 0xaf, 0x0f, 0xe2, 0x91, 0x30,
    0x6c, 0xcc, 0xa7, 0x22, 0x68, 0xcb, 0xe7, 0xeb, 0x65, 0xf6, 0xf0, 0x01, 0x74, 0x1d, 0xd1, 0x0f,
    0x10, 0x68, 0x4f, 0x57, 0x25, 0x82, 0x8b, 0xee, 0x84, 0x55, 0x1e, 0xc2, 0xae, 0x03, 0xdf, 0x4e,
    0x11, 0x56, 0x24, 0xda, 0xcf, 0x37, 0x43, 0x03, 0xef, 0x7a, 0x86, 0x8b, 0x40, 0x2b, 0xc4, 0x81,
    0x3c, 0x74, 0x33, 0xb6, 0x30, 0x71, 0x65, 0xef, 0xde, 0x96, 0x18, 0xa8, 0x96, 0xd7, 0xcf, 0x6c,
    0x5e, 0xe7, 0x4e, 0xda, 0x42, 0xc7, 0xdd, 0xd2, 0xaa, 0xf7, 0xd5, 0x00, 0x54, 0x5a, 0x5b, 0x92,
    0x76, 0xd2, 0x0e, 0x42, 0xc4, 0x20, 0x22, 0x93, 0x16, 0x36, 0xd7, 0xba, 0x62, 0xca, 0x65, 0x62,
    0xa9, 0xbd, 0xa6, 0x8c, 0x64, 0x00, 0x06, 0xc2, 0x87, 0xe4, 0x9e, 0xf9, 0xb5, 0xd3, 0x31, 0x58,
    0xff, 0xc6, 0x2c, 0x8e, 0x8f, 0x12, 0x7e, 0x66, 0x98, 0x9b, 0x68, 0xcd, 0xb5, 0x85, 0x63, 0x3e,
    0xdd, 0xcd, 0xee, 0x0b, 0xa9, 0x46, 0x95, 0x64, 0x8d, 0x5b, 0xe3, 0x57, 0x76, 0xce, 0xe9, 0xd4,
    0x48, 0x85, 0x9d, 0x98, 0x31, 0x54, 0x91, 0x6b, 0xe6, 0xec, 0x47, 0x24, 0x42, 0xd6, 0xb9, 0xef,
    0xa8, 0x1d, 0xb9, 0xd9, 0x8f, 0xe2, 0x09, 0x10, 0xaf, 0x98, 0x6c, 0x37, 0xe9, 0x4b, 0xb4, 0x7f,
    0xc8, 0x94, 0x93, 0x4b, 0x47, 0x32,
];

const YUBIKEY_5CI_INTERMEDIATE: [u8; 746] = [
    0x30, 0x82, 0x02, 0xe6, 0x30, 0x82, 0x01, 0xce, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
    0xa4, 0xff, 0x76, 0xa6, 0xb1, 0xa2, 0x16, 0xe2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x2b, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x20, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x50, 0x49, 0x56, 0x20, 0x52,
    0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20, 0x32, 0x36,
    0x33, 0x37, 0x35, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x33, 0x31, 0x34, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x35, 0x32, 0x30, 0x34, 0x31, 0x37, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x16, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x50, 0x49, 0x56, 0x20, 0x41, 0x74,
    0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
    0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc0, 0x38, 0x4f, 0xdd, 0x85, 0x08,
    0xc8, 0xb5, 0x92, 0x8e, 0xc7, 0x88, 0x28, 0xdc, 0xcc, 0xb1, 0xca, 0x82, 0x76, 0x27, 0x2c, 0x96,
    0xb7, 0x64, 0xc4, 0xf8, 0x0c, 0xa0, 0xaf, 0x0e, 0x73, 0x1b, 0xb4, 0x7a, 0xba, 0xf8, 0xca, 0xf1,
    0x57, 0x89, 0x26, 0x59, 0x2f, 0x7d, 0x81, 0x4d, 0x96, 0x0b, 0x0f, 0xc3, 0x7b, 0x63, 0xe7, 0x75,
    0x73, 0x0c, 0x3a, 0x55, 0x5b, 0x05, 0x61, 0xdc, 0x27, 0xd3, 0x52, 0x9c, 0xe9, 0x82, 0xeb, 0xc0,
    0xce, 0x45, 0x20, 0xdf, 0xe6, 0xb1, 0x79, 0x06, 0x4c, 0xf7, 0x4f, 0x56, 0x15, 0x5e, 0xa8, 0xd3,
    0x07, 0x87, 0x84, 0x32, 0x62, 0xb6, 0x22, 0xc7, 0x05, 0x9a, 0x4d, 0xb0, 0xc2, 0x1a, 0x84, 0x03,
    0x6b, 0x15, 0x65, 0x89, 0xf5, 0x66, 0x3d, 0x2d, 0x36, 0x32, 0xf9, 0xbc, 0x34, 0x38, 0xc2, 0xd7,
    0xb5, 0xf7, 0x2e, 0x1b, 0x15, 0xd4, 0xe8, 0x92, 0xff, 0x03, 0x92, 0x72, 0xc2, 0x3c, 0x1c, 0x71,
    0xa0, 0x41, 0x74, 0x08, 0x40, 0x40, 0xcc, 0x9e, 0xde, 0x9c, 0xc1, 0x9f, 0x37, 0x40, 0xae, 0xf7,
    0xed, 0x6b, 0xae, 0xe6, 0xe8, 0x52, 0xcd, 0x3d, 0xe3, 0x54, 0xec, 0xf6, 0xf1, 0x19, 0xe2, 0x8f,
    0x5a, 0x7f, 0xf0, 0xf7, 0x15, 0x59, 0xc1, 0x8a, 0x58, 0x23, 0xd5, 0x60, 0xd6, 0xc2, 0x98, 0x27,
    0x5c, 0x9b, 0xfb, 0x10, 0x78, 0x90, 0x7c, 0xcb, 0x96, 0x84, 0x44, 0x36, 0x9e, 0x3c, 0x82, 0x19,
    0xbf, 0xd6, 0xb1, 0x9c, 0x34, 0xf4, 0x0e, 0x75, 0x0e, 0xed, 0xa0, 0xe9, 0xcd, 0x70, 0x3b, 0x8b,
    0xb5, 0xcf, 0x6e, 0xb9, 0x22, 0x48, 0x11, 0x29, 0xed, 0x10, 0xaa, 0x5c, 0x6b, 0x39, 0x70, 0x1a,
    0x86, 0x09, 0xba, 0xbf, 0xff, 0x11, 0xa1, 0xfb, 0xf0, 0x06, 0xb4, 0x20, 0x95, 0xfe, 0xc4, 0x0c,
    0x9d, 0x38, 0xe5, 0xd1, 0xdd, 0xa4, 0xd9, 0x0f, 0x17, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
    0x15, 0x30, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03,
    0x03, 0x04, 0x03, 0x05, 0x02, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x70, 0xa7, 0xa7, 0x79, 0x39, 0x91,
    0x06, 0x81, 0xc1, 0x89, 0x91, 0xf6, 0x75, 0x07, 0x28, 0x66, 0x35, 0x76, 0x00, 0xaf, 0x84, 0x95,
    0x25, 0x5f, 0x64, 0x80, 0xc9, 0x8d, 0x9f, 0x51, 0xe6, 0x8c, 0xb9, 0x44, 0x5c, 0x45, 0x19, 0x56,
    0x04, 0x5c, 0x3a, 0x0a, 0xf2, 0xc0, 0x8e, 0xf4, 0xac, 0xe4, 0x3c, 0xb7, 0x3b, 0xa2, 0x56, 0x0e,
    0x69, 0x3e, 0xd5, 0x61, 0x59, 0xa3, 0x45, 0x0c, 0xaf, 0x5e, 0x56, 0x64, 0x58, 0x92, 0xe4, 0x5a,
    0x72, 0xd0, 0xcf, 0x86, 0x5a, 0xf0, 0x42, 0x44, 0xfd, 0xd8, 0x99, 0xb4, 0xb0, 0xf8, 0x9d, 0xad,
    0x93, 0x25, 0xb2, 0xa4, 0x22, 0x08, 0xbb, 0xb7, 0x0c, 0xb4, 0xba, 0x51, 0x62, 0x42, 0xf9, 0x48,
    0x09, 0x56, 0x99, 0x40, 0x80, 0xcf, 0xc7, 0x59, 0x3e, 0x4e, 0x45, 0x2c, 0xfa, 0x5e, 0xaa, 0x6c,
    0x60, 0x42, 0x74, 0x68, 0x49, 0x27, 0xba, 0xec, 0x85, 0xe2, 0xbf, 0x76, 0xcd, 0xc8, 0xf0, 0x35,
    0xdc, 0xda, 0x17, 0x23, 0x6c, 0x70, 0xd2, 0x15, 0x90, 0x53, 0x5f, 0xbc, 0xe6, 0xd7, 0xd3, 0xc6,
    0x84, 0xf1, 0x3a, 0x20, 0x33, 0x63, 0xc5, 0x29, 0x01, 0x3d, 0x86, 0x82, 0x0b, 0x52, 0x98, 0x2c,
    0x0e, 0xde, 0xc1, 0xec, 0x1c, 0x95, 0x18, 0x5d, 0x1c, 0x82, 0x7f, 0xc7, 0xba, 0x8e, 0xd2, 0x4b,
    0x38, 0x50, 0x71, 0xfe, 0xec, 0xfe, 0x54, 0x9a, 0x11, 0x1f, 0xb8, 0x54, 0x54, 0xe6, 0x3e, 0xb1,
    0xb3, 0xf9, 0x24, 0x9f, 0x37, 0x75, 0x1a, 0xd6, 0x66, 0x44, 0xb9, 0xec, 0x77, 0xf7, 0xab, 0x42,
    0xce, 0xb5, 0xb9, 0xf6, 0xee, 0xf3, 0x3e, 0x7e, 0x62, 0xf4, 0xcb, 0xbc, 0xf8, 0xbe, 0x00, 0xe8,
    0x0d, 0xe7, 0x66, 0xae, 0x6b, 0x1b, 0x3e, 0xdb, 0x11, 0x73, 0x7b, 0x7b, 0x45, 0x6a, 0x2a, 0x09,
    0xaf, 0x34, 0x22, 0xad, 0x63, 0x3e, 0xf7, 0x66, 0xe6, 0x0c,
];

#[test]
pub fn test_5c_attestation_verification() {
    let attested_key_data = verification::verify_certificate_chain(
        &YUBIKEY_5CI_ATTESTATION,
        &YUBIKEY_5CI_INTERMEDIATE,
        None,
    )
    .unwrap();

    assert_eq!(attested_key_data.serial, 11778047);
    assert_eq!(attested_key_data.firmware, "5.2.4");
    assert_eq!(attested_key_data.touch_policy, 3);
    assert_eq!(attested_key_data.pin_policy, 1);
}
