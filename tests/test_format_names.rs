extern crate base64;
extern crate openssl;

extern crate certificate_carver;

use std::io::{Cursor, Read, Seek, SeekFrom};
use openssl::x509::X509;

use certificate_carver::format_issuer_subject;
use certificate_carver::x509;

fn test_format_names_helper(pem: &[u8], expected: &str) {
    let cert = X509::from_pem(pem).unwrap();
    let mut cur: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    format_issuer_subject(&cert, &mut cur).unwrap();
    cur.seek(SeekFrom::Start(0)).unwrap();
    let mut string = String::new();
    cur.read_to_string(&mut string).unwrap();
    println!("{}", string);
    assert!(string == expected);
}

#[test]
fn test_format_names_rootca() {
    test_format_names_helper(
        include_bytes!("files/bespoke/rootca.crt"),
        "issuer=C=US O=Test Root CA ST=Minnesota L=Minneapolis, subject=C=US O=Test Root CA ST=Minnesota L=Minneapolis"
    );
}

#[test]
fn test_format_names_entrust_teletextstring() {
    test_format_names_helper(
        include_bytes!("files/collected/entrust_teletexstring.pem"),
        "issuer=O=Entrust.net OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.) OU=(c) 1999 Entrust.net Limited CN=Entrust.net Certification Authority (2048), subject=O=Entrust.net OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.) OU=(c) 1999 Entrust.net Limited CN=Entrust.net Certification Authority (2048)"
    );
}

#[test]
fn test_format_names_verisign_printablestring() {
    test_format_names_helper(
        include_bytes!("files/collected/verisign_printablestring.pem"),
        "issuer=C=US O=VeriSign, Inc. OU=VeriSign Trust Network OU=(c) 1999 VeriSign, Inc. - For authorized use only CN=VeriSign Class 3 Public Primary Certification Authority - G3, subject=C=US O=VeriSign, Inc. OU=VeriSign Trust Network OU=(c) 1999 VeriSign, Inc. - For authorized use only CN=VeriSign Class 3 Public Primary Certification Authority - G3"
    );
}

#[test]
fn test_format_names_emptyissuername() {
    test_format_names_helper(
        include_bytes!("files/collected/emptyIssuerName.pem"),
        "issuer=, subject=CN=End entity signed by empty name CA"
    )
}

fn decode_pem(pem_data: &[u8]) -> Vec<u8> {
    let mut pem_data = pem_data;
    if pem_data.ends_with(b"\n") {
        pem_data = &pem_data[..pem_data.len() - 1];
    }
    let prefix = b"-----BEGIN CERTIFICATE-----";
    let suffix = b"-----END CERTIFICATE-----";
    assert!(pem_data.starts_with(prefix));
    assert!(pem_data.ends_with(suffix));
    let base64_data = pem_data[prefix.len() .. pem_data.len() - suffix.len()].to_vec();
    let config = base64::Config::new(base64::CharacterSet::Standard, true, true, base64::LineWrap::Wrap(64, base64::LineEnding::CRLF));
    base64::decode_config(&base64_data, config).unwrap()
}

fn test_format_names_new_helper(pem: &[u8], expected: &str) {
    let cert = x509::CertificateBytes(decode_pem(pem));
    let mut cur: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let (issuer, subject) = cert.parse_cert_names().unwrap();
    cert.format_issuer_subject(issuer, subject, &mut cur).unwrap();
    cur.seek(SeekFrom::Start(0)).unwrap();
    let mut string = String::new();
    cur.read_to_string(&mut string).unwrap();
    println!("{}", string);
    assert!(string == expected);
}

#[test]
fn test_format_names_new_rootca() {
    test_format_names_new_helper(
        include_bytes!("files/bespoke/rootca.crt"),
        "issuer=C=US O=Test Root CA ST=Minnesota L=Minneapolis, subject=C=US O=Test Root CA ST=Minnesota L=Minneapolis"
    );
}

#[test]
fn test_format_names_new_entrust_teletextstring() {
    test_format_names_new_helper(
        include_bytes!("files/collected/entrust_teletexstring.pem"),
        "issuer=O=Entrust.net OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.) OU=(c) 1999 Entrust.net Limited CN=Entrust.net Certification Authority (2048), subject=O=Entrust.net OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.) OU=(c) 1999 Entrust.net Limited CN=Entrust.net Certification Authority (2048)"
    );
}

#[test]
fn test_format_names_new_verisign_printablestring() {
    test_format_names_new_helper(
        include_bytes!("files/collected/verisign_printablestring.pem"),
        "issuer=C=US O=VeriSign, Inc. OU=VeriSign Trust Network OU=(c) 1999 VeriSign, Inc. - For authorized use only CN=VeriSign Class 3 Public Primary Certification Authority - G3, subject=C=US O=VeriSign, Inc. OU=VeriSign Trust Network OU=(c) 1999 VeriSign, Inc. - For authorized use only CN=VeriSign Class 3 Public Primary Certification Authority - G3"
    );
}

#[test]
fn test_format_names_new_emptyissuername() {
    test_format_names_new_helper(
        include_bytes!("files/collected/emptyIssuerName.pem"),
        "issuer=, subject=CN=End entity signed by empty name CA"
    )
}
