#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut file_carver = certificate_carver::FileCarver::new();
    let mut cursor = std::io::Cursor::new(data);
    file_carver.carve_file(&mut cursor);
});
