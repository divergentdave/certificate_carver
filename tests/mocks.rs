extern crate reqwest;
extern crate serde_json;

extern crate certificate_carver;

use reqwest::Url;
use std::cell::RefCell;

use certificate_carver::ctlog::{AddChainResponse, GetRootsResponse, LogInfo, LogServers};
use certificate_carver::{APIError, CertificateChain, CertificateFingerprint, CrtShServer};

#[derive(Default)]
pub struct MockCrtShServer();

impl CrtShServer for MockCrtShServer {
    fn check_crtsh(&self, _fp: &CertificateFingerprint) -> Result<bool, APIError> {
        Ok(false)
    }
}

#[derive(Default)]
pub struct MockLogServers {
    pub submitted_chains: RefCell<Vec<(Url, CertificateChain)>>,
}

impl MockLogServers {
    pub fn new() -> MockLogServers {
        MockLogServers {
            submitted_chains: RefCell::new(Vec::new()),
        }
    }
}

impl LogServers for MockLogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, APIError> {
        let url_str = log.get_url().as_str();
        let json_str;
        if url_str == "https://ct.googleapis.com/pilot/" {
            json_str = include_str!("roots/pilot.json");
        } else if url_str == "https://ct.googleapis.com/daedalus/" {
            json_str = include_str!("roots/daedalus.json");
        } else if url_str == "https://ct.googleapis.com/icarus/" {
            json_str = include_str!("roots/icarus.json");
        } else if url_str == "https://ct1.digicert-ct.com/log/" {
            json_str = include_str!("roots/digicert-ct1.json");
        } else if url_str == "https://dodo.ct.comodo.com/" {
            json_str = include_str!("roots/dodo.json");
        } else if url_str == "https://sabre.ct.comodo.com/" {
            json_str = include_str!("roots/sabre.json");
        } else if url_str == "https://mammoth.ct.comodo.com/" {
            json_str = include_str!("roots/mammoth.json");
        } else if url_str == "https://plausible.ct.nordu.net/" {
            json_str = include_str!("roots/plausible.json");
        } else {
            panic!("No mock data is stored for {}", url_str);
        }
        Ok(serde_json::from_str(json_str).unwrap())
    }

    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, APIError> {
        let resp: AddChainResponse = serde_json::from_str(
            "{\"sct_version\":0,\"id\":\"pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=\",\"timestamp\":1519606625707,\"extensions\":\"\",\"signature\":\"BAMARzBFAiEAmqLo0/5CaAgNZdpsBgDKFAwKgQ4g2fLfMTUe8LLEYVQCIDhUD2coHB7IOV844lDSpm5Tmfh7FGaWtCFOZnSxGYiK\"}"
        ).unwrap();
        let mut storage = self.submitted_chains.borrow_mut();
        storage.push((log.get_url().clone(), chain.clone()));
        Ok(resp)
    }
}
