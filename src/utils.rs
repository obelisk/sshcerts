/// Takes an ASN1 encode ECDSA signature and attempts to
/// parse it into it's R and S constituent parts
pub fn asn_der_to_r_s(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 ||  buf[0] != 0x30 {
        return None;
    }
    let buf = &buf[3..];
    let r_length = buf[0] as usize;
    if buf.len() < r_length + 2 {
        return None;
    }
    let buf = &buf[1..];
    let r = &buf[..r_length];
    let buf = &buf[r_length..];
    if buf[0] != 0x2 {
        return None
    }
    let s_length = buf[1] as usize;
    let s = &buf[2..];

    if s.len() != s_length {
        return None
    }

    Some((r, s))
}