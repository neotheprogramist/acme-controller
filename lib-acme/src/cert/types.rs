use std::fmt::Display;

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use josekit::jwk::alg::ec::EcKeyPair;
use serde::Deserialize;
use serde::Serialize;
use super::errors::AcmeErrors;
use clap::ValueEnum;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectoryUrls {
    pub(crate) new_nonce: String,
    pub(crate) new_account: String,
    pub(crate) new_order: String,
    // The fields below were added later and old `AccountCredentials` may not have it.
    // Newer deserialized account credentials grab a fresh set of `DirectoryUrls` on
    // deserialization, so they should be fine. Newer fields should be optional, too.
    pub(crate) new_authz: Option<String>,
    pub(crate) revoke_cert: Option<String>,
    pub(crate) key_change: Option<String>,
}

pub(crate) fn base64(data: &impl Serialize) -> Result<String, AcmeErrors> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
}
#[derive(Debug, PartialEq,Clone)]
pub(crate) enum OrderStatus {
    Valid,
    Invalid,
    Pending,
    Ready,
    Processing,
    Unknown, // Default case for any unrecognized status
}

impl From<&str> for OrderStatus {
    fn from(status: &str) -> Self {
        match status {
            "valid" => OrderStatus::Valid,
            "invalid" => OrderStatus::Invalid,
            "pending" => OrderStatus::Pending,
            "ready" => OrderStatus::Ready,
            "processing" => OrderStatus::Processing,
            _ => OrderStatus::Unknown,
        }
    }
}
/// Represents the types of challenges supported by the ACME protocol for domain validation.
///
/// Each challenge type corresponds to a specific method of proving control over a domain.
/// These challenges are part of the process to securely issue certificates.
///
/// # Variants
///
/// - `Dns01`: Represents the DNS-01 challenge which involves creating a DNS record to prove control of a domain .
/// - `Http01`: NOT IMPLEMENTED - Represents the HTTP-01 challenge where a file must be made available at a specific URL on the domain.
/// - `TlsAlpn01`: NOT IMPLEMENTED - Represents the TLS-ALPN-01 challenge that involves proving control over a domain by responding to TLS connections in a specific way.
#[derive(Debug, PartialEq, Clone)]
pub enum ChallangeType {
    Dns01,
    Http01,
    TlsAlpn01,
}
impl From<&str> for ChallangeType {
    fn from(challange_type: &str) -> Self {
        match challange_type {
            "dns-01" => ChallangeType::Dns01,
            "http-01" => ChallangeType::Http01,
            "tls-alpn-01" => ChallangeType::TlsAlpn01,
            _ => panic!("Invalid challange type"),
        }
    }
}
impl Display for ChallangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallangeType::Dns01 => write!(f, "dns-01"),
            ChallangeType::Http01 => write!(f, "http-01"),
            ChallangeType::TlsAlpn01 => write!(f, "tls-alpn-01"),
        }
    }
}

#[derive(Debug,Clone,Serialize,Deserialize, PartialEq,ValueEnum)]
pub enum Environment {
    Staging,
    Production,
}
impl Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Staging => write!(f, "staging"),
            Environment::Production => write!(f, "production")
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct AccountCredentials {
    pub(crate) account_url: String,
    pub(crate) account_key: EcKeyPair,
}
#[derive(Debug, Clone)]
pub(crate) struct Order {
    pub(crate) url: String,
    pub(crate) status: OrderStatus,
    pub(crate) finalize_url: String,
    pub(crate) identifiers: Vec<String>,
    pub(crate) authorizations: Vec<String>,
    pub(crate) certificate: Option<String>,
}
impl Order {
    pub(crate) async fn update_status(&mut self)->Result<(),AcmeErrors>{
        let client = reqwest::Client::new();
        let response = client.get(&self.url).send().await?;
        let order_status: Value = response.json().await?;
        let status_str = order_status["status"]
        .as_str()
        .ok_or(AcmeErrors::ConversionError)?;
        let status = OrderStatus::from(status_str);
        self.status = status;
        if self.status == OrderStatus::Valid {
            self.certificate = Some(order_status["certificate"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_owned());
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Challange{
    pub(crate) url:String,
    pub(crate) domain:String,
}
pub(crate) struct Token{
    pub(crate) domain:String,
    pub(crate) token:String,
}