extern crate certificate_carver;

mod utils;

use certificate_carver::x509::Certificate;
use certificate_carver::CertificateBytes;

use crate::utils::decode_pem;

#[test]
fn test_year_rootca() {
    let cert = Certificate::parse(decode_pem(include_bytes!("files/bespoke/rootca.crt"))).unwrap();
    assert_eq!(cert.get_not_after_year(), 2028);
}

#[test]
fn test_year_entrust_teletextstring() {
    let cert = Certificate::parse(decode_pem(include_bytes!(
        "files/collected/entrust_teletexstring.pem"
    )))
    .unwrap();
    assert_eq!(cert.get_not_after_year(), 2029);
}

#[test]
fn test_year_verisign_printablestring() {
    let cert = Certificate::parse(decode_pem(include_bytes!(
        "files/collected/verisign_printablestring.pem"
    )))
    .unwrap();
    assert_eq!(cert.get_not_after_year(), 2036);
}

#[test]
fn test_year_davidsherenowitsa_party() {
    let cert = Certificate::parse(CertificateBytes(
        include_bytes!("files/davidsherenowitsa.party/cert.der").to_vec(),
    ))
    .unwrap();
    assert_eq!(cert.get_not_after_year(), 2018);
}
