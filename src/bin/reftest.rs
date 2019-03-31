extern crate openssl;

extern crate certificate_carver;

use std::collections::hash_map::DefaultHasher;
use std::env::args;
use std::hash::{Hash, Hasher};

use certificate_carver::Carver;

fn main() {
    let mut carver = Carver::new(Vec::new());
    let mut empty_args = true;
    let mut iter = args();
    iter.next(); // skip argv[0]
    for arg in iter {
        carver.scan_directory_or_file(&arg);
        empty_args = false;
    }
    if empty_args {
        panic!("pass at least one directory as a command line argument");
    }

    let mut match_count = 0;
    let mut mismatch_count = 0;
    for (_fp, info1) in carver.fp_map.iter() {
        match &info1.openssl_cert {
            Some(openssl_cert_1) => {
                for (_fp, info2) in carver.fp_map.iter() {
                    match &info2.openssl_cert {
                        Some(openssl_cert_2) => {
                            let issued = openssl_cert_1.issued(&openssl_cert_2)
                                == openssl::x509::X509VerifyResult::OK;

                            let mut hash1 = DefaultHasher::new();
                            info1.cert.get_subject().hash(&mut hash1);
                            let hash1 = hash1.finish();
                            let mut hash2 = DefaultHasher::new();
                            info2.cert.get_issuer().hash(&mut hash2);
                            let hash2 = hash2.finish();
                            let hash_match = hash1 == hash2;

                            if issued == hash_match {
                                match_count += 1;
                            } else {
                                let mut name1: Vec<u8> = Vec::new();
                                let mut name2: Vec<u8> = Vec::new();
                                info1.cert.format_issuer_subject(&mut name1).unwrap();
                                info2.cert.format_issuer_subject(&mut name2).unwrap();
                                let name1 = String::from_utf8(name1).unwrap();
                                let name2 = String::from_utf8(name2).unwrap();
                                println!(
                                    "Did {} issue {}? OpenSSL says {}, hashes say {}",
                                    name1, name2, issued, hash_match
                                );
                                mismatch_count += 1;
                            }
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
    println!(
        "Issued vs. DN hashes: {} pairs matched, {} pairs didn't match",
        match_count, mismatch_count
    );
}
