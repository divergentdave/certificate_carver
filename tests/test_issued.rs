extern crate openssl;

extern crate certificate_carver;

mod utils;

use openssl::x509::{X509, X509VerifyResult};

use certificate_carver::x509;

use utils::decode_pem;

#[test]
fn test_issued_bespoke() {
    let root_cert = X509::from_pem(include_bytes!("files/bespoke/rootca.crt")).unwrap();
    let root_to_a = X509::from_pem(include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt")).unwrap();
    let root_to_b = X509::from_pem(include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt")).unwrap();
    let a_to_b = X509::from_pem(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt")).unwrap();
    let b_to_a = X509::from_pem(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt")).unwrap();

    assert!(root_cert.issued(&root_cert) == X509VerifyResult::OK);
    assert!(root_cert.issued(&root_to_a) == X509VerifyResult::OK);
    assert!(root_cert.issued(&root_to_b) == X509VerifyResult::OK);
    assert!(root_cert.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(root_cert.issued(&b_to_a) != X509VerifyResult::OK);

    assert!(root_to_a.issued(&root_cert) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&a_to_b) == X509VerifyResult::OK);
    assert!(root_to_a.issued(&b_to_a) != X509VerifyResult::OK);

    assert!(root_to_b.issued(&root_cert) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&b_to_a) == X509VerifyResult::OK);

    assert!(a_to_b.issued(&root_cert) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&b_to_a) == X509VerifyResult::OK);

    assert!(b_to_a.issued(&root_cert) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&a_to_b) == X509VerifyResult::OK);
    assert!(b_to_a.issued(&b_to_a) != X509VerifyResult::OK);
}

fn temp_issued(parent_cert: &x509::CertificateBytes, child_cert: &x509::CertificateBytes) -> bool {
    // TODO: need to improve certificate data model, parse names up front, put them in a struct
    let parent_subject = parent_cert.parse_cert_names().unwrap().1;
    let child_issuer = child_cert.parse_cert_names().unwrap().0;
    parent_subject == child_issuer
}

#[test]
fn test_issued_new_bespoke() {
    let root_cert = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/rootca.crt")));
    let root_to_a = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt")));
    let root_to_b = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt")));
    let a_to_b = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt")));
    let b_to_a = x509::CertificateBytes(decode_pem(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt")));

    assert!(temp_issued(&root_cert, &root_cert));
    assert!(temp_issued(&root_cert, &root_to_a));
    assert!(temp_issued(&root_cert, &root_to_b));
    assert!(!temp_issued(&root_cert, &a_to_b));
    assert!(!temp_issued(&root_cert, &b_to_a));

    assert!(!temp_issued(&root_to_a, &root_cert));
    assert!(!temp_issued(&root_to_a, &root_to_a));
    assert!(!temp_issued(&root_to_a, &root_to_b));
    assert!(temp_issued(&root_to_a, &a_to_b));
    assert!(!temp_issued(&root_to_a, &b_to_a));

    assert!(!temp_issued(&root_to_b, &root_cert));
    assert!(!temp_issued(&root_to_b, &root_to_a));
    assert!(!temp_issued(&root_to_b, &root_to_b));
    assert!(!temp_issued(&root_to_b, &a_to_b));
    assert!(temp_issued(&root_to_b, &b_to_a));

    assert!(!temp_issued(&a_to_b, &root_cert));
    assert!(!temp_issued(&a_to_b, &root_to_a));
    assert!(!temp_issued(&a_to_b, &root_to_b));
    assert!(!temp_issued(&a_to_b, &a_to_b));
    assert!(temp_issued(&a_to_b, &b_to_a));

    assert!(!temp_issued(&b_to_a, &root_cert));
    assert!(!temp_issued(&b_to_a, &root_to_a));
    assert!(!temp_issued(&b_to_a, &root_to_b));
    assert!(temp_issued(&b_to_a, &a_to_b));
    assert!(!temp_issued(&b_to_a, &b_to_a));
}
