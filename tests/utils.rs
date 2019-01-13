extern crate base64;

pub fn decode_pem(pem_data: &[u8]) -> Vec<u8> {
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
    base64::decode_config(&base64_data, config).unwrap()
}
