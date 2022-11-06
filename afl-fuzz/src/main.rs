use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        let mut file_carver = certificate_carver::FileCarver::new();
        let mut cursor = std::io::Cursor::new(data);
        file_carver.carve_file(&mut cursor);
    });
}
