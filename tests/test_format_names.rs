extern crate openssl;

extern crate certificate_carver;

use std::io::{Cursor, Read, Seek, SeekFrom};
use openssl::x509::X509;

use certificate_carver::format_issuer_subject;

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
