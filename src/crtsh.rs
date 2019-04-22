use reqwest::Url;
use sled::{self, Db};
use std::path::Path;
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::{APIError, CertificateFingerprint};

pub trait CrtShServer {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError>;
}

pub struct RealCrtShServer<'a> {
    client: &'a reqwest::Client,
}

impl<'a> RealCrtShServer<'a> {
    pub fn new(client: &'a reqwest::Client) -> RealCrtShServer<'a> {
        RealCrtShServer { client }
    }
}

impl CrtShServer for RealCrtShServer<'_> {
    // true: certificate has already been indexed
    // false: certificate has not been indexed
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError> {
        let url_str = format!("https://crt.sh/?q={}", fp);
        let url = Url::parse(&url_str).unwrap();
        let mut resp = self.client.get(url).send()?;
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

pub struct DelayCrtShServer<'a> {
    inner: &'a CrtShServer,
    delay: Duration,
    last_request: Mutex<Instant>,
}

impl<'a> DelayCrtShServer<'a> {
    pub fn new(inner: &'a CrtShServer, delay: Duration) -> DelayCrtShServer<'a> {
        DelayCrtShServer {
            inner,
            delay,
            last_request: Mutex::new(Instant::now() - delay),
        }
    }
}

impl CrtShServer for DelayCrtShServer<'_> {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, APIError> {
        {
            let mut guard = self.last_request.lock().unwrap();
            let mut now = Instant::now();
            let elapsed = now.duration_since(*guard);
            if elapsed < self.delay {
                let sleep_duration = self.delay - elapsed;
                sleep(sleep_duration);
                now = Instant::now();
            }
            *guard = now;
        }
        self.inner.check_crtsh(fp)
    }
}
