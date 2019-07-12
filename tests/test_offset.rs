use std::io::Cursor;

use certificate_carver::FileCarver;

const MAX_PADDING: usize = 10 * 1024 * 1024;
const PADDINGS: [usize; 8] = [
    0,
    1,
    512,
    1024,
    1024 * 1024,
    5 * 1024 * 1024,
    10 * 1024 * 1024 - 1,
    10 * 1024 * 1024,
];

#[test]
fn test_offset_pem_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut padded = vec![0; MAX_PADDING];
    padded.extend_from_slice(bytes);
    let padded = padded;
    let file_carver = FileCarver::new();
    for padding in PADDINGS.iter() {
        let offset: usize = MAX_PADDING - *padding;
        let mut stream = Cursor::new(&padded[offset..]);
        let certs = file_carver.carve_file(&mut stream);
        assert_eq!(certs.len(), 2, "padding is {}", padding);
    }
}

#[test]
fn test_offset_der_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut padded = vec![0; MAX_PADDING];
    padded.extend_from_slice(bytes);
    let padded = padded;
    let file_carver = FileCarver::new();
    for padding in PADDINGS.iter() {
        let offset: usize = MAX_PADDING - *padding;
        let mut stream = Cursor::new(&padded[offset..]);
        let certs = file_carver.carve_file(&mut stream);
        assert_eq!(certs.len(), 1, "padding is {}", padding);
    }
}

#[test]
fn test_pem_then_der() {
    let pem_bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let der_bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut vec1 = vec![0; MAX_PADDING];
    vec1.extend_from_slice(pem_bytes);
    let vec1 = vec1;
    let zeros = &vec1[..MAX_PADDING];
    let file_carver = FileCarver::new();
    for padding_infix in PADDINGS.iter() {
        let mut vec2 = vec1.clone();
        vec2.extend_from_slice(&zeros[..*padding_infix]);
        vec2.extend_from_slice(der_bytes);
        for padding_prefix in PADDINGS.iter() {
            let offset: usize = MAX_PADDING - *padding_prefix;
            let mut stream = Cursor::new(&vec2[offset..]);
            let certs = file_carver.carve_file(&mut stream);
            assert_eq!(
                certs.len(),
                3,
                "prefix padding is {}, infix padding is {}",
                padding_prefix,
                padding_infix
            );
        }
    }
}

#[test]
fn test_der_then_pem() {
    let der_bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let pem_bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut vec1 = vec![0; MAX_PADDING];
    vec1.extend_from_slice(der_bytes);
    let vec1 = vec1;
    let zeros = &vec1[..MAX_PADDING];
    let file_carver = FileCarver::new();
    for padding_infix in PADDINGS.iter() {
        let mut vec2 = vec1.clone();
        vec2.extend_from_slice(&zeros[..*padding_infix]);
        vec2.extend_from_slice(pem_bytes);
        for padding_prefix in PADDINGS.iter() {
            let offset: usize = MAX_PADDING - *padding_prefix;
            let mut stream = Cursor::new(&vec2[offset..]);
            let certs = file_carver.carve_file(&mut stream);
            assert_eq!(
                certs.len(),
                3,
                "prefix padding is {}, infix padding is {}",
                padding_prefix,
                padding_infix
            );
        }
    }
}
