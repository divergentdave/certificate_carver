#![feature(repeat_generic_slice)]
#![feature(test)]
extern crate test;

use certificate_carver::FileCarver;
use std::convert::TryInto;
use std::io::{Cursor, Seek, SeekFrom};
use test::Bencher;

#[bench]
fn bench_carve_matches(b: &mut Bencher) {
    const BYTES: &[u8] = include_bytes!("../tests/files/davidsherenowitsa.party/fullchain.pem");
    let repeated = BYTES.repeat(100);
    let mut stream = Cursor::new(&repeated);
    let file_carver = FileCarver::new();
    b.bytes = repeated.len().try_into().unwrap();
    b.iter(|| {
        file_carver.carve_stream(&mut stream);
        stream.seek(SeekFrom::Start(0)).unwrap();
    });
}
