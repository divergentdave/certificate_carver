extern crate base64;

extern crate certificate_carver;

use certificate_carver::CertificateBytes;

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
    let config = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::Wrap(64, base64::LineEnding::CRLF),
    );
    CertificateBytes(base64::decode_config(&base64_data, config).unwrap())
}
