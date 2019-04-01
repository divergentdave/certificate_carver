use crate::{
    pem_base64_decode, pem_base64_encode, APIError, Certificate, CertificateBytes,
    CertificateChain, CertificateFingerprint,
};
use reqwest::Url;
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
}

pub struct LogInfo {
    url: Url,
    pub roots: Vec<Certificate>,
    pub trust_roots: TrustRoots,
    pub shard: LogShard,
}

impl LogInfo {
    pub fn new(url: &str, shard: LogShard) -> LogInfo {
        LogInfo {
            url: Url::parse(url).unwrap(),
            roots: Vec::new(),
            trust_roots: TrustRoots::new(),
            shard,
        }
    }

    pub fn fetch_roots(&mut self, log_comms: &LogServers) -> Result<(), Box<std::error::Error>> {
        let body = log_comms.fetch_roots_resp(self)?;
        let mut vec = Vec::new();
        for encoded in body.certificates {
            match pem_base64_decode(&encoded) {
                Ok(bytes) => {
                    let bytes = CertificateBytes(bytes);
                    match Certificate::parse(bytes) {
                        Ok(cert) => vec.push(cert),
                        Err(_) => println!(
                            "Warning: Couldn't parse a trusted root certificate from {}",
                            self.url
                        ),
                    }
                }
                Err(_) => println!("Warning: Couldn't decode trusted roots from {}", self.url),
            }
        }
        self.roots = vec;
        self.trust_roots.add_roots(&self.roots);
        Ok(())
    }

    pub fn get_url(&self) -> &Url {
        &self.url
    }

    pub fn will_accept_year(&self, not_after_year: u64) -> bool {
        match self.shard {
            LogShard::Any => true,
            LogShard::ExpiryYear(year) => year == not_after_year,
        }
    }
}

pub trait LogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, APIError>;
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, APIError>;
}

pub struct RealLogServers();

impl LogServers for RealLogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, APIError> {
        let url = log.get_url().join("ct/v1/get-roots").unwrap();
        let mut resp = reqwest::get(url)?;
        resp.json().map_err(APIError::Network)
    }

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
        let client = reqwest::Client::new();
        let mut response = client.post(url).json(&request_body).send()?;
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
