extern crate openssl;

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

    let mut match_count = 0;
    let mut mismatch_count = 0;
    for (_fp, info) in carver.map.iter() {
        let mut text1: Vec<u8> = Vec::new();
        format_issuer_subject(&info.cert, &mut text1).unwrap();

        let mut text2: Vec<u8> = Vec::new();
        let cert2 = x509::CertificateInfo::new(info.der.0.clone()).unwrap();
        cert2.format_issuer_subject(&mut text2).unwrap();

        if text1 == text2 {
            match_count += 1;
        } else {
            println!("{}", info.paths[0]);
            println!("Mismatch");
            println!("{}", String::from_utf8(text1).unwrap());
            println!("{}", String::from_utf8(text2).unwrap());
            mismatch_count += 1;
        }
    }
    println!("Names: {} certificates matched, {} certificates didn't match", match_count, mismatch_count);

    let mut match_count = 0;
    let mut mismatch_count = 0;
    for (_fp, info1) in carver.map.iter() {
        for (_fp, info2) in carver.map.iter() {
            let issued_old = info1.cert.issued(&info2.cert) == openssl::x509::X509VerifyResult::OK;

            let cert1_new = x509::CertificateInfo::new(info1.der.0.clone()).unwrap();
            let cert2_new = x509::CertificateInfo::new(info2.der.0.clone()).unwrap();
            let issued_new = cert1_new.issued(&cert2_new);

            if issued_old == issued_new {
                match_count += 1;
            } else {
                let mut name1: Vec<u8> = Vec::new();
                let mut name2: Vec<u8> = Vec::new();
                cert1_new.format_issuer_subject(&mut name1).unwrap();
                cert2_new.format_issuer_subject(&mut name2).unwrap();
                let name1 = String::from_utf8(name1).unwrap();
                let name2 = String::from_utf8(name2).unwrap();
                println!("Did {} issue {}? OpenSSL says {}, new code says {}", name1, name2, issued_old, issued_new);
                mismatch_count += 1;
            }
        }
    }
    println!("Issued: {} pairs matched, {} pairs didn't match", match_count, mismatch_count);
}
