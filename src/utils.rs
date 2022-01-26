/// Takes an ASN1 encoded ECDSA signature and attempts to
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

/// Most signature systems generate ECDSA signatures encoded in ASN1 format.
/// This function will take an ASN1 encoded ECDSA signature and return
/// an SSH Signature blob
pub fn signature_convert_asn1_ecdsa_to_ssh(signature: &[u8]) -> Option<Vec<u8>> {
    let (r,s) = match asn_der_to_r_s(signature) {
        Some((r,s)) => (r, s),
        None => return None,
    };
    let mut sig_encoding: Vec<u8> = Vec::new();
    sig_encoding.extend_from_slice(&(r.len() as u32).to_be_bytes());
    sig_encoding.extend_from_slice(r);
    sig_encoding.extend_from_slice(&(s.len() as u32).to_be_bytes());
    sig_encoding.extend_from_slice(s);

    Some(sig_encoding)
}