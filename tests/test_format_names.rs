extern crate base64;
extern crate openssl;

extern crate certificate_carver;

use std::io::{Cursor, Read, Seek, SeekFrom};
use openssl::x509::X509;

use certificate_carver::format_issuer_subject;
use certificate_carver::x509;

#[test]
fn test_format_names() {
    let cert = X509::from_pem(include_bytes!("files/bespoke/rootca.crt")).unwrap();
    let mut cur: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    format_issuer_subject(&cert, &mut cur).unwrap();
    cur.seek(SeekFrom::Start(0)).unwrap();
    let mut string = String::new();
    cur.read_to_string(&mut string).unwrap();
    println!("{}", string);
    assert!(string == "issuer=C=US O=Test Root CA ST=Minnesota L=Minneapolis, subject=C=US O=Test Root CA ST=Minnesota L=Minneapolis");
}

fn decode_pem(pem_data: &[u8]) -> Vec<u8> {
    let prefix = b"-----BEGIN CERTIFICATE-----";
    let suffix = b"-----END CERTIFICATE-----\n";
    assert!(pem_data.starts_with(prefix));
    assert!(pem_data.ends_with(suffix));
    let base64_data = pem_data[prefix.len() .. pem_data.len() - suffix.len()].to_vec();
    let config = base64::Config::new(base64::CharacterSet::Standard, true, true, base64::LineWrap::Wrap(64, base64::LineEnding::CRLF));
    base64::decode_config(&base64_data, config).unwrap()
}

#[test]
fn test_format_names_new() {
    let cert = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/rootca.crt")));
    let mut cur: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let (issuer, subject) = cert.parse_cert_names().unwrap();
    cert.format_issuer_subject(issuer, subject, &mut cur).unwrap();
    cur.seek(SeekFrom::Start(0)).unwrap();
    let mut string = String::new();
    cur.read_to_string(&mut string).unwrap();
    println!("{}", string);
    assert!(string == "issuer=C=US O=Test Root CA ST=Minnesota L=Minneapolis, subject=C=US O=Test Root CA ST=Minnesota L=Minneapolis");
}
