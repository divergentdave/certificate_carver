use reqwest::Url;
use sled::{self, Db};
use std::path::Path;

use crate::{APIError, CertificateFingerprint};

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

pub struct CachedCrtShServer<'a> {
    inner: &'a CrtShServer,
    tree: Db,
}

impl<'a> CachedCrtShServer<'a> {
    pub fn new(inner: &'a CrtShServer, path: &Path) -> sled::Result<CachedCrtShServer<'a>> {
        let tree = Db::start_default(path)?;
        Ok(CachedCrtShServer { inner, tree })
    }
}

impl<'a> CrtShServer for CachedCrtShServer<'a> {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError> {
        if let Ok(Some(_)) = self.tree.get(fp.as_ref()) {
            return Ok(true);
        }
        let result = self.inner.check_crtsh(fp)?;
        if result {
            if let Err(_) = self.tree.set(fp.as_ref().clone(), Vec::new()) {
                println!("Warning: Couldn't write to cache file");
            }
        }
        Ok(result)
    }
}
