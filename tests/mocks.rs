extern crate serde_json;

extern crate certificate_carver;

use std::cell::RefCell;

use certificate_carver::ctlog::{AddChainResponse, GetRootsResponse, LogInfo, LogServers};
use certificate_carver::{CertificateChain, CertificateFingerprint, CrtShServer};

#[derive(Default)]
pub struct MockCrtShServer();

impl CrtShServer for MockCrtShServer {
    fn check_crtsh(&self, _fp: &CertificateFingerprint) -> Result<bool, Box<std::error::Error>> {
        Ok(false)
    }
}

#[derive(Debug)]
struct MockLogError(String);

impl std::fmt::Display for MockLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MockLogError {}

#[derive(Default)]
pub struct MockLogServers {
    pub add_chain_count: RefCell<usize>,
}

impl MockLogServers {
    pub fn new() -> MockLogServers {
        MockLogServers {
            add_chain_count: RefCell::new(0),
        }
    }
}

impl LogServers for MockLogServers {
    fn fetch_roots_resp(&self, log: &LogInfo) -> Result<GetRootsResponse, Box<std::error::Error>> {
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
            return Err(Box::new(MockLogError(format!(
                "No mock data is stored for {}",
                url_str
            ))));
        }
        serde_json::from_str(json_str)
            .map_err(|e: serde_json::Error| -> Box<std::error::Error> { Box::new(e) })
    }

    fn submit_chain(
        &self,
        _log: &LogInfo,
        _chain: &CertificateChain,
    ) -> Result<Result<AddChainResponse, reqwest::StatusCode>, Box<std::error::Error>> {
        let resp: AddChainResponse = serde_json::from_str(
            "{\"sct_version\":0,\"id\":\"pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=\",\"timestamp\":1519606625707,\"extensions\":\"\",\"signature\":\"BAMARzBFAiEAmqLo0/5CaAgNZdpsBgDKFAwKgQ4g2fLfMTUe8LLEYVQCIDhUD2coHB7IOV844lDSpm5Tmfh7FGaWtCFOZnSxGYiK\"}"
        )?;
        let mut count = self.add_chain_count.borrow_mut();
        *count += 1;
        Ok(Ok(resp))
    }
}
