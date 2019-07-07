#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let carver = certificate_carver::Carver::new(Vec::new());
    let mut cursor = std::io::Cursor::new(data);
    carver.carve_stream(&mut cursor);
});
