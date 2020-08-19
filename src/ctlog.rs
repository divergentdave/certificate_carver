use crate::{
    pem_base64_decode, pem_base64_encode, ApiError, Certificate, CertificateBytes,
    CertificateChain, CertificateFingerprint,
};
use async_std::task::block_on;
use chrono::{Datelike, Utc};
use json::{self, JsonValue};
use lazy_static::lazy_static;
use std::collections::HashSet;
use surf::url::Url;

pub struct GetRootsResponse {
    certificates: Vec<String>,
}

impl GetRootsResponse {
    pub fn parse(text: &str) -> Result<Self, ApiError> {
        if let JsonValue::Object(object) = json::parse(text)? {
            match object.get("certificates") {
                Some(JsonValue::Array(array)) => Ok(GetRootsResponse {
                    certificates: array
                        .iter()
                        .map(|jv| {
                            jv.as_str()
                                .map(ToOwned::to_owned)
                                .ok_or(ApiError::InvalidResponse("bad certificate"))
                        })
                        .collect::<Result<Vec<String>, ApiError>>()?,
                }),
                Some(_) => Err(ApiError::InvalidResponse("bad certificates")),
                None => Err(ApiError::InvalidResponse("missing certificates")),
            }
        } else {
            Err(ApiError::InvalidResponse("not an object"))
        }
    }
}

pub struct AddChainRequest {
    chain: Vec<String>,
}

impl AddChainRequest {
    pub fn dump(self) -> String {
        let vec = self.chain.into_iter().map(JsonValue::String).collect();
        let mut object = json::object::Object::with_capacity(1);
        object.insert("chain", JsonValue::Array(vec));
        JsonValue::Object(object).dump()
    }
}

#[derive(Debug)]
pub struct AddChainResponse {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

impl AddChainResponse {
    pub fn parse(text: &str) -> Result<Self, ApiError> {
        if let JsonValue::Object(object) = json::parse(text)? {
            Ok(AddChainResponse {
                sct_version: object
                    .get("sct_version")
                    .ok_or(ApiError::InvalidResponse("missing sct_version"))?
                    .as_u8()
                    .ok_or(ApiError::InvalidResponse("bad sct_version"))?,
                id: object
                    .get("id")
                    .ok_or(ApiError::InvalidResponse("missing id"))?
                    .as_str()
                    .ok_or(ApiError::InvalidResponse("bad id"))?
                    .to_owned(),
                timestamp: object
                    .get("timestamp")
                    .ok_or(ApiError::InvalidResponse("missing timestamp"))?
                    .as_u64()
                    .ok_or(ApiError::InvalidResponse("bad timestamp"))?,
                extensions: object
                    .get("extensions")
                    .ok_or(ApiError::InvalidResponse("missing extensions"))?
                    .as_str()
                    .ok_or(ApiError::InvalidResponse("bad extensions"))?
                    .to_owned(),
                signature: object
                    .get("signature")
                    .ok_or(ApiError::InvalidResponse("missing signature"))?
                    .as_str()
                    .ok_or(ApiError::InvalidResponse("bad signature"))?
                    .to_owned(),
            })
        } else {
            Err(ApiError::InvalidResponse("not an object"))
        }
    }
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
        let body = GetRootsResponse::parse(json_str).expect("Error parsing bundled log roots");
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
    ) -> Result<AddChainResponse, ApiError>;
}

pub struct RealLogServers<'a, C: surf::middleware::HttpClient> {
    client: &'a surf::Client<C>,
}

impl<'a, C: surf::middleware::HttpClient> RealLogServers<'a, C> {
    pub fn new(client: &'a surf::Client<C>) -> RealLogServers<'a, C> {
        RealLogServers { client }
    }
}

impl<C: surf::middleware::HttpClient> LogServers for RealLogServers<'_, C> {
    fn submit_chain(
        &self,
        log: &LogInfo,
        chain: &CertificateChain,
    ) -> Result<AddChainResponse, ApiError> {
        let url = log.url.join("ct/v1/add-chain").unwrap();
        let encoded = chain
            .0
            .iter()
            .map(|c| pem_base64_encode(c.as_ref()))
            .collect();
        let request_body = AddChainRequest { chain: encoded };
        let mut response = block_on(
            self.client
                .post(url)
                .set_header("Content-Type", "application/json")
                .body_bytes(request_body.dump())
                .middleware(crate::add_user_agent_header),
        )?;
        if !response.status().is_success() {
            return Err(ApiError::Status(response.status()));
        }
        let response_body = AddChainResponse::parse(&block_on(response.body_string())?)?;
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

#[cfg(test)]
mod tests {
    use super::AddChainRequest;

    #[test]
    fn test_submit_chain_serialize() {
        let request = AddChainRequest {
            chain: vec!["test".to_owned()],
        };
        assert_eq!(request.dump(), "{\"chain\":[\"test\"]}");
    }
}
