use std::cell::RefCell;

use surf::Url;

use crate::crtsh::CrtShServer;
use crate::ctlog::{AddChainResponse, LogInfo, LogServers};
use crate::{ApiError, CertificateChain, CertificateFingerprint};

pub struct MockCrtShServer {
    response: bool,
}

impl MockCrtShServer {
    #[allow(dead_code)]
    pub fn always_true() -> MockCrtShServer {
        MockCrtShServer { response: true }
    }

    pub fn always_false() -> MockCrtShServer {
        MockCrtShServer { response: false }
    }
}

impl Default for MockCrtShServer {
    fn default() -> MockCrtShServer {
        MockCrtShServer::always_false()
    }
}

impl CrtShServer for MockCrtShServer {
    fn check_crtsh(&self, _fp: &CertificateFingerprint) -> Result<bool, ApiError> {
        Ok(self.response)
    }
}

#[derive(Default)]
pub struct MockLogServers {
    pub submitted_chains: RefCell<Vec<(Url, CertificateChain)>>,
}

impl MockLogServers {
    #[allow(dead_code)]
    pub fn new() -> MockLogServers {
        MockLogServers {
            submitted_chains: RefCell::new(Vec::new()),
        }
    }
}

impl LogServers for MockLogServers {
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, ApiError> {
        let resp = AddChainResponse::parse(
            "{\"sct_version\":0,\"id\":\"pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=\",\"timestamp\":1519606625707,\"extensions\":\"\",\"signature\":\"BAMARzBFAiEAmqLo0/5CaAgNZdpsBgDKFAwKgQ4g2fLfMTUe8LLEYVQCIDhUD2coHB7IOV844lDSpm5Tmfh7FGaWtCFOZnSxGYiK\"}"
        ).unwrap();
        let mut storage = self.submitted_chains.borrow_mut();
        storage.push((log.get_url().clone(), chain.clone()));
        Ok(resp)
    }
}
