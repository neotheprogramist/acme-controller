use super::errors::AcmeErrors;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use clap::ValueEnum;
use josekit::jwk::alg::ec::EcKeyPair;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_with::{serde_as, DisplayFromStr};
use std::fmt::Display;
use url::Url;

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectoryUrls {
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) new_nonce: Url,
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) new_account: Url,
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) new_order: Url,
    // Optional fields use the same approach but wrapped in Option
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub(crate) new_authz: Option<Url>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub(crate) revoke_cert: Option<Url>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub(crate) key_change: Option<Url>,
}

pub(crate) fn base64(data: &impl Serialize) -> Result<String, AcmeErrors> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
}
#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ValueEnum)]
pub enum Environment {
    Staging,
    Production,
}
impl Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Staging => write!(f, "staging"),
            Environment::Production => write!(f, "production"),
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct AccountCredentials {
    pub(crate) account_url: Url,
    pub(crate) account_key: EcKeyPair,
}
#[derive(Debug, Clone)]
pub(crate) struct Order {
    pub(crate) url: Url,
    pub(crate) status: OrderStatus,
    pub(crate) finalize_url: Url,
    pub(crate) identifiers: Vec<String>,
    pub(crate) authorizations: Vec<String>,
    pub(crate) certificate: Option<Url>,
}
impl Order {
    pub(crate) async fn update_status(&mut self) -> Result<(), AcmeErrors> {
        let client = reqwest::Client::new();
        let response = client.get(self.url.clone()).send().await?;
        let order_status: Value = response.json().await?;
        let status_str = order_status["status"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?;
        let status = OrderStatus::from(status_str);
        self.status = status;
        if self.status == OrderStatus::Valid {
            let certificate_str = Some(
                order_status["certificate"]
                    .as_str()
                    .ok_or(AcmeErrors::ConversionError)?
                    .to_owned(),
            );
            self.certificate =
                Url::parse(&certificate_str.ok_or(AcmeErrors::ConversionError)?).ok();
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Challange {
    pub(crate) url: Url,
    pub(crate) domain: String,
}
pub(crate) struct Token {
    pub(crate) domain: String,
    pub(crate) token: String,
}
