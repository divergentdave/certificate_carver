use base64::Engine;

use certificate_carver::CertificateBytes;

// This was removed from base64 in version 0.10.0
fn copy_without_whitespace(input: &[u8]) -> Vec<u8> {
    let mut input_copy = Vec::<u8>::with_capacity(input.len());
    input_copy.extend(input.iter().filter(|b| !b" \n\t\r\x0b\x0c".contains(b)));

    input_copy
}

pub fn decode_pem(pem_data: &[u8]) -> CertificateBytes {
    let mut pem_data = pem_data;
    if pem_data.ends_with(b"\n") {
        pem_data = &pem_data[..pem_data.len() - 1];
    }
    let prefix = b"-----BEGIN CERTIFICATE-----";
    let suffix = b"-----END CERTIFICATE-----";
    assert!(pem_data.starts_with(prefix));
    assert!(pem_data.ends_with(suffix));
    let base64_data = pem_data[prefix.len()..pem_data.len() - suffix.len()].to_vec();
    CertificateBytes(
        base64::engine::general_purpose::STANDARD
            .decode(copy_without_whitespace(base64_data.as_ref()))
            .unwrap(),
    )
}
