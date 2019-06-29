use crate::{
    pem_base64_decode, pem_base64_encode, APIError, Certificate, CertificateBytes,
    CertificateChain, CertificateFingerprint,
};
use chrono::{Datelike, Utc};
use lazy_static::lazy_static;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Deserialize)]
pub struct GetRootsResponse {
    certificates: Vec<String>,
}

#[derive(Serialize)]
pub struct AddChainRequest {
    chain: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct AddChainResponse {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

pub enum LogShard {
    Any,
    ExpiryYear(u64),
    AlreadyExpired,
}

pub struct LogInfo {
    url: Url,
    pub roots: Vec<Certificate>,
    pub trust_roots: TrustRoots,
    pub shard: LogShard,
}

impl LogInfo {
    pub fn new(url: &str, shard: LogShard, roots_json: &str) -> LogInfo {
        let mut log = LogInfo {
            url: Url::parse(url).unwrap(),
            roots: Vec::new(),
            trust_roots: TrustRoots::new(),
            shard,
        };
        log.parse_roots(roots_json);
        log
    }

    fn parse_roots(&mut self, json_str: &str) {
        let body: GetRootsResponse = serde_json::from_str(json_str).unwrap();
        let mut vec = Vec::new();
        for encoded in body.certificates {
            let bytes = CertificateBytes(pem_base64_decode(&encoded).unwrap());
            let cert = Certificate::parse(bytes).unwrap();
            vec.push(cert);
        }
        self.roots = vec;
        self.trust_roots.add_roots(&self.roots);
    }

    pub fn get_url(&self) -> &Url {
        &self.url
    }

    pub fn will_accept_year(&self, not_after_year: u64) -> bool {
        match self.shard {
            LogShard::Any => true,
            LogShard::ExpiryYear(year) => year == not_after_year,
            LogShard::AlreadyExpired => {
                lazy_static! {
                    static ref CURRENT_YEAR: u64 = Utc::today().year() as u64;
                }
                not_after_year < *CURRENT_YEAR
            }
        }
    }
}

pub trait LogServers {
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, APIError>;
}

pub struct RealLogServers<'a> {
    client: &'a reqwest::Client,
}

impl<'a> RealLogServers<'a> {
    pub fn new(client: &'a reqwest::Client) -> RealLogServers<'a> {
        RealLogServers { client }
    }
}

impl LogServers for RealLogServers<'_> {
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, APIError> {
        let url = log.url.join("ct/v1/add-chain").unwrap();
        let encoded = chain
            .0
            .iter()
            .map(|c| pem_base64_encode(c.as_ref()))
            .collect();
        let request_body = AddChainRequest { chain: encoded };
        let mut response = self.client.post(url).json(&request_body).send()?;
        if !response.status().is_success() {
            return Err(APIError::Status(response.status()));
        }
        let response_body: AddChainResponse = response.json()?;
        Ok(response_body)
    }
}

#[derive(Default)]
pub struct TrustRoots {
    root_fps: HashSet<CertificateFingerprint>,
}

impl TrustRoots {
    pub fn new() -> TrustRoots {
        TrustRoots {
            root_fps: HashSet::new(),
        }
    }

    pub fn add_roots(&mut self, roots: &[Certificate]) {
        for root in roots.iter() {
            let fp = root.fingerprint();
            self.root_fps.insert(fp);
        }
    }

    pub fn test_fingerprint(&self, fp: &CertificateFingerprint) -> bool {
        self.root_fps.contains(fp)
    }
}
