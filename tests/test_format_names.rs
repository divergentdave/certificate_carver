extern crate certificate_carver;

mod utils;

use std::io::{Cursor, Read, Seek, SeekFrom};

use certificate_carver::x509::Certificate;

use utils::decode_pem;

fn test_format_names_helper(pem: &[u8], expected: &str) {
    let cert = Certificate::new(decode_pem(pem)).unwrap();
    let mut cur: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    cert.format_issuer_subject(&mut cur).unwrap();
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
