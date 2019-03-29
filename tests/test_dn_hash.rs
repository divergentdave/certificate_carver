extern crate certificate_carver;

mod utils;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use certificate_carver::x509::Certificate;

use crate::utils::decode_pem;

fn get_hash<H: Hash>(v: H) -> u64 {
    let mut hasher = DefaultHasher::new();
    v.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn test_hashes_bespoke() {
    let root_cert =
        Certificate::parse(decode_pem(include_bytes!("files/bespoke/rootca.crt"))).unwrap();
    let root_to_a = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_a_signed_by_rootca.crt"
    )))
    .unwrap();
    let root_to_b = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_b_signed_by_rootca.crt"
    )))
    .unwrap();
    let a_to_b = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt"
    )))
    .unwrap();
    let b_to_a = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt"
    )))
    .unwrap();

    let root_cert_issuer_hash = get_hash(root_cert.get_issuer());
    let root_cert_subject_hash = get_hash(root_cert.get_subject());
    let root_to_a_issuer_hash = get_hash(root_to_a.get_issuer());
    let root_to_a_subject_hash = get_hash(root_to_a.get_subject());
    let root_to_b_issuer_hash = get_hash(root_to_b.get_issuer());
    let root_to_b_subject_hash = get_hash(root_to_b.get_subject());
    let a_to_b_issuer_hash = get_hash(a_to_b.get_issuer());
    let a_to_b_subject_hash = get_hash(a_to_b.get_subject());
    let b_to_a_issuer_hash = get_hash(b_to_a.get_issuer());
    let b_to_a_subject_hash = get_hash(b_to_a.get_subject());

    assert_eq!(root_cert_subject_hash, root_cert_issuer_hash);
    assert_eq!(root_cert_subject_hash, root_to_a_issuer_hash);
    assert_eq!(root_cert_subject_hash, root_to_b_issuer_hash);
    assert_ne!(root_cert_subject_hash, a_to_b_issuer_hash);
    assert_ne!(root_cert_subject_hash, b_to_a_issuer_hash);

    assert_ne!(root_to_a_subject_hash, root_cert_issuer_hash);
    assert_ne!(root_to_a_subject_hash, root_to_a_issuer_hash);
    assert_ne!(root_to_a_subject_hash, root_to_b_issuer_hash);
    assert_eq!(root_to_a_subject_hash, a_to_b_issuer_hash);
    assert_ne!(root_to_a_subject_hash, b_to_a_issuer_hash);

    assert_ne!(root_to_b_subject_hash, root_cert_issuer_hash);
    assert_ne!(root_to_b_subject_hash, root_to_a_issuer_hash);
    assert_ne!(root_to_b_subject_hash, root_to_b_issuer_hash);
    assert_ne!(root_to_b_subject_hash, a_to_b_issuer_hash);
    assert_eq!(root_to_b_subject_hash, b_to_a_issuer_hash);

    assert_ne!(a_to_b_subject_hash, root_cert_issuer_hash);
    assert_ne!(a_to_b_subject_hash, root_to_a_issuer_hash);
    assert_ne!(a_to_b_subject_hash, root_to_b_issuer_hash);
    assert_ne!(a_to_b_subject_hash, a_to_b_issuer_hash);
    assert_eq!(a_to_b_subject_hash, b_to_a_issuer_hash);

    assert_ne!(b_to_a_subject_hash, root_cert_issuer_hash);
    assert_ne!(b_to_a_subject_hash, root_to_a_issuer_hash);
    assert_ne!(b_to_a_subject_hash, root_to_b_issuer_hash);
    assert_eq!(b_to_a_subject_hash, a_to_b_issuer_hash);
    assert_ne!(b_to_a_subject_hash, b_to_a_issuer_hash);
}

#[test]
fn test_hashes_ignore_case() {
    let cert1 = Certificate::parse(decode_pem(include_bytes!(
        "files/collected/test_end_entity.pem"
    )))
    .unwrap();
    let cert2 = Certificate::parse(decode_pem(include_bytes!(
        "files/collected/issued_by_ee.pem"
    )))
    .unwrap();

    let cert1_subject = cert1.get_subject();
    let cert2_issuer = cert2.get_issuer();
    let cert1_subject_hash = get_hash(cert1_subject);
    let cert2_issuer_hash = get_hash(cert2_issuer);

    assert_ne!(cert1_subject.as_ref(), cert2_issuer.as_ref());
    assert_eq!(cert1_subject_hash, cert2_issuer_hash);
}
