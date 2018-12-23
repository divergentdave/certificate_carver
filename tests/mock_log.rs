extern crate serde_json;

extern crate certificate_carver;

use certificate_carver::{LogServers, LogInfo, CertificateChain, CertificateBytes, AddChainResponse};

pub struct MockLogServers();

impl LogServers for MockLogServers {
    fn fetch_roots(&self, _log: &mut LogInfo) -> Result<Vec<CertificateBytes>, Box<std::error::Error>>{
        Ok(Vec::new())
    }

    fn submit_chain(&self, _log: &LogInfo, _chain: &CertificateChain) -> Result<Result<AddChainResponse, reqwest::StatusCode>, Box<std::error::Error>> {
        let resp: AddChainResponse = serde_json::from_str(
            "{}"
        )?;
        Ok(Ok(resp))
    }
}
