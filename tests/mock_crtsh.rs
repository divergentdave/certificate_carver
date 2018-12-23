extern crate certificate_carver;

use certificate_carver::{CrtShServer, CertificateFingerprint};

pub struct MockCrtShServer();

impl CrtShServer for MockCrtShServer {
    fn check_crtsh (&self, _fp: &CertificateFingerprint) -> Result<bool, Box<std::error::Error>> {
        return Ok(true)
    }
}
