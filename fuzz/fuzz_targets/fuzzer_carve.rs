#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate certificate_carver;

fuzz_target!(|data: &[u8]| {
    let carver = certificate_carver::Carver::new(Vec::new());
    let mut cursor = std::io::Cursor::new(data);
    carver.carve_stream(&mut cursor);
});
