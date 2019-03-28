use crate::{
    pem_base64_decode, pem_base64_encode, CertificateBytes, CertificateChain,
    CertificateFingerprint,
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

pub struct LogInfo {
    url: Url,
    pub roots: Vec<CertificateBytes>,
    pub trust_roots: TrustRoots,
}

impl LogInfo {
    pub fn new(url: &str) -> LogInfo {
        LogInfo {
            url: Url::parse(url).unwrap(),
            roots: Vec::new(),
            trust_roots: TrustRoots::new(),
        }
    }

    pub fn fetch_roots(
        &self,
        log_comms: &LogServers,
    ) -> Result<Vec<CertificateBytes>, Box<std::error::Error>> {
        let body = log_comms.fetch_roots_resp(self)?;
        let mut vec = Vec::new();
        for encoded in body.certificates {
            let bytes = pem_base64_decode(&encoded).unwrap();
            vec.push(CertificateBytes(bytes));
        }
        Ok(vec)
    }

    fn submit_chain(
        &self,
        chain: &CertificateChain,
    ) -> Result<Result<AddChainResponse, reqwest::StatusCode>, Box<std::error::Error>> {
        // TODO: which order? should have leaf first, i think we're okay
        let url = self.url.join("ct/v1/add-chain").unwrap();
        let encoded = chain
            .0
            .iter()
            .map(|c| pem_base64_encode(c.as_ref()))
            .collect();
        let request_body = AddChainRequest { chain: encoded };
        let client = reqwest::Client::new();
        let mut response = client.post(url).json(&request_body).send()?;
        if !response.status().is_success() {
            return Ok(Err(response.status()));
        }
        let response_body: AddChainResponse = response.json()?;
        Ok(Ok(response_body))
    }

    pub fn get_url(&self) -> &Url {
        &self.url
    }
}

pub trait LogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, Box<std::error::Error>>;
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<Result<AddChainResponse, reqwest::StatusCode>, Box<std::error::Error>>;
}

pub struct RealLogServers();

impl LogServers for RealLogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, Box<std::error::Error>> {
        let url = log.get_url().join("ct/v1/get-roots")?;
        let mut resp = reqwest::get(url)?;
        resp.json()
            .map_err(|e: reqwest::Error| -> Box<std::error::Error> { Box::new(e) })
    }

    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<Result<AddChainResponse, reqwest::StatusCode>, Box<std::error::Error>> {
        log.submit_chain(chain)
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

    pub fn add_roots(&mut self, roots: &[CertificateBytes]) {
        for root in roots.iter() {
            let fp = root.fingerprint();
            self.root_fps.insert(fp);
        }
    }

    pub fn test_fingerprint(&self, fp: &CertificateFingerprint) -> Result<(), ()> {
        if self.root_fps.contains(fp) {
            Ok(())
        } else {
            Err(())
        }
    }
}
