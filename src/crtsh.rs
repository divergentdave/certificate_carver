use async_std::task::block_on;
use sled::{Db, Tree};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};
use surf::Url;

use crate::{ApiError, CertificateFingerprint};

pub trait CrtShServer {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, ApiError>;
}

pub struct RealCrtShServer<'a> {
    client: &'a surf::Client,
}

impl<'a> RealCrtShServer<'a> {
    pub fn new(client: &'a surf::Client) -> RealCrtShServer<'a> {
        RealCrtShServer { client }
    }
}

impl CrtShServer for RealCrtShServer<'_> {
    // true: certificate has already been indexed
    // false: certificate has not been indexed
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, ApiError> {
        let url_str = format!("https://crt.sh/?q={}", fp);
        let url = Url::parse(&url_str).unwrap();
        let mut resp = block_on(self.client.get(url))?;
        if !resp.status().is_success() {
            return Err(ApiError::Status(resp.status()));
        }
        let body = block_on(resp.body_string())?;
        match body.find("Certificate not found") {
            None => Ok(true),
            Some(_) => Ok(false),
        }
    }
}

pub struct CachedCrtShServer<T: CrtShServer> {
    inner: T,
    tree: Tree,
}

impl<T: CrtShServer> CachedCrtShServer<T> {
    const TREE_NAME: &'static str = "crtsh-cache";

    pub fn new(inner: T, db: Db) -> sled::Result<CachedCrtShServer<T>> {
        let tree = db.open_tree(Self::TREE_NAME)?;
        Ok(CachedCrtShServer { inner, tree })
    }

    pub fn new_temporary(inner: T) -> sled::Result<CachedCrtShServer<T>> {
        let config = sled::Config::default().temporary(true);
        let db = config.open()?;
        let tree = db.open_tree(Self::TREE_NAME)?;
        Ok(CachedCrtShServer { inner, tree })
    }
}

impl<T: CrtShServer> CrtShServer for CachedCrtShServer<T> {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, ApiError> {
        if let Ok(Some(_)) = self.tree.get(fp.as_ref()) {
            return Ok(true);
        }
        let in_crtsh = self.inner.check_crtsh(fp)?;
        if in_crtsh {
            let sled_result = self.tree.insert(fp.as_ref(), Vec::new());
            if sled_result.is_err() {
                println!("Warning: Couldn't write to cache file");
            }
        }
        Ok(in_crtsh)
    }
}

pub struct RetryDelayCrtShServer<T: CrtShServer> {
    inner: T,
    delay: Duration,
    state: Mutex<RetryDelayState>,
}

struct RetryDelayState {
    last_request: Instant,
}

impl<T: CrtShServer> RetryDelayCrtShServer<T> {
    pub fn new(inner: T, delay: Duration) -> RetryDelayCrtShServer<T> {
        let state = RetryDelayState {
            last_request: Instant::now() - delay,
        };
        RetryDelayCrtShServer {
            inner,
            delay,
            state: Mutex::new(state),
        }
    }
}

impl<T: CrtShServer> CrtShServer for RetryDelayCrtShServer<T> {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, ApiError> {
        let mut guard = self.state.lock().unwrap();
        let mut error_count = 0;
        loop {
            let mut now = Instant::now();
            let elapsed = now.duration_since((*guard).last_request);
            let delay = self.delay * (1 << error_count);
            if elapsed < delay {
                let sleep_duration = delay - elapsed;
                sleep(sleep_duration);
                now = Instant::now();
            }
            (*guard).last_request = now;

            let result = self.inner.check_crtsh(fp);
            match result {
                Ok(_) => return result,
                Err(_) => error_count += 1,
            }
            println!("Request to crt.sh failed, waiting and retrying...");
        }
    }
}
