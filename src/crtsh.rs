use crate::{APIError, CertificateFingerprint};
use reqwest::Url;

pub trait CrtShServer {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError>;
}

pub struct RealCrtShServer();

impl CrtShServer for RealCrtShServer {
    // true: certificate has already been indexed
    // false: certificate has not been indexed
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError> {
        let url_str = format!("https://crt.sh/?q={}", fp);
        let url = Url::parse(&url_str).unwrap();
        let mut resp = reqwest::get(url)?;
        if !resp.status().is_success() {
            return Err(APIError::Status(resp.status()));
        }
        let body = resp.text()?;
        match body.find("Certificate not found") {
            None => Ok(true),
            Some(_) => Ok(false),
        }
    }
}
