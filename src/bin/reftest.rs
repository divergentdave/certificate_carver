extern crate certificate_carver;

use std::env::args;

use certificate_carver::{Carver, format_issuer_subject};
use certificate_carver::x509;

fn main() {
    let mut carver = Carver::new();
    let mut empty_args = true;
    let mut iter = args();
    iter.next();  // skip argv[0]
    for arg in iter {
        carver.scan_directory(&arg);
        empty_args = false;
    }
    if empty_args {
        panic!("pass at least one directory as a command line argument");
    }

    for (_fp, info) in carver.map.iter() {
        println!("{}", info.paths[0]);
        let mut text1: Vec<u8> = Vec::new();
        format_issuer_subject(&info.cert, &mut text1).unwrap();

        let mut text2: Vec<u8> = Vec::new();
        let cert2 = x509::CertificateBytes(info.der.0.clone());
        let (issuer, subject) = cert2.parse_cert_names().unwrap();
        issuer.parse_rdns().unwrap();
        subject.parse_rdns().unwrap();
        cert2.format_issuer_subject(issuer, subject, &mut text2).unwrap();

        if text1 == text2 {
            println!("Match");
        } else {
            println!("Mismatch");
            println!("{}", String::from_utf8(text1).unwrap());
            println!("{}", String::from_utf8(text2).unwrap());
        }
    }
}
