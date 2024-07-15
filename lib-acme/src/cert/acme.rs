use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
use serde::Serialize;
use serde_json::Value;
use url::Url;
extern crate tracing;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::types::{AccountCredentials, Challange, ChallangeType, Order, OrderStatus, Token};
use super::{create_jws::create_jws, types::DirectoryUrls};
use crate::cert::crypto::get_key_authorization;
use crate::cert::dns_menagment::post_dns_record;
const REPLAY_NONCE: &str = "replay-nonce";

#[derive(Serialize)]
pub(crate) struct Identifier {
    #[serde(rename = "type")]
    pub(crate) type_: String,
    pub(crate) value: String,
}

impl Identifier {
    pub(crate) fn new(value: &str) -> Self {
        Identifier {
            type_: "dns".to_string(),
            value: value.to_string(),
        }
    }
}

pub(crate) async fn new_directory(dir_url: &Url) -> Result<DirectoryUrls, AcmeErrors> {
    let client = Client::new();
    let response = client.get(dir_url.to_string()).send().await?;
    Ok(response.json().await?)
}

pub(crate) async fn new_nonce(client: &Client, url_value: Url) -> Result<String, AcmeErrors> {
    let response = client.head(url_value).send().await?;
    let nonce = response
        .headers()
        .get(REPLAY_NONCE)
        .ok_or(AcmeErrors::MissingNonce)?
        .to_str()?
        .to_string();
    Ok(nonce)
}
pub(crate) async fn new_account(
    client: &Client,
    urls: DirectoryUrls,
    contact_mail: Vec<String>,
    ec_key_pair: EcKeyPair,
) -> Result<AccountCredentials, AcmeErrors> {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.new_nonce.clone()).await?;
    let _ = payload.set_claim("termsOfServiceAgreed", Some(serde_json::Value::Bool(true)));
    let contact_values = contact_mail
        .iter()
        .map(|email| serde_json::Value::String(format!("mailto:{}", email)))
        .collect::<Vec<_>>();

    let _ = payload.set_claim("contact", Some(serde_json::Value::Array(contact_values)));
    let body = create_jws(
        &nonce,
        &payload,
        urls.new_account.clone(),
        &ec_key_pair,
        None,
    )?;
    let response = post(client, urls.new_account.clone(), body).await?;
    if response.status().as_u16() != 201 {
        Err(AcmeErrors::AccountError)
    } else {
        parse_account(response, ec_key_pair)
    }
}
pub(crate) fn parse_account(
    response: Response,
    ec_key_pair: EcKeyPair,
) -> Result<AccountCredentials, AcmeErrors> {
    let account_url = response
        .headers()
        .get("location")
        .ok_or(AcmeErrors::MissingLocationHeader)?
        .to_str()?
        .to_owned();
    let url = Url::parse(&account_url).map_err(|_| AcmeErrors::ConversionError)?;
    Ok(AccountCredentials {
        account_url: url,
        account_key: ec_key_pair,
    })
}

pub(crate) async fn submit_order(
    client: &Client,
    urls: DirectoryUrls,
    identifiers: Vec<&str>,
    ec_key_pair: EcKeyPair,
    kid: Url,
) -> Result<Order, AcmeErrors> {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.clone().new_nonce).await?;
    let identifier_objects = identifiers
        .iter()
        .map(|x| Identifier::new(x))
        .collect::<Vec<Identifier>>();
    let identifiers_json =
        serde_json::to_value(identifier_objects).expect("Failed to serialize identifiers");
    let _ = payload.set_claim("identifiers", Some(identifiers_json));
    let body = create_jws(
        &nonce,
        &payload,
        urls.new_order.clone(),
        &ec_key_pair,
        Some(kid),
    )?;
    let response = post(client, urls.new_order, body).await?;
    if response.status().as_u16() != 201 {
        Err(AcmeErrors::OrderError)
    } else {
        parse_order(response).await
    }
}
pub(crate) async fn parse_order(response: reqwest::Response) -> Result<Order, AcmeErrors> {
    let url = response
        .headers()
        .get("location")
        .ok_or(AcmeErrors::MissingLocationHeader)?
        .to_str()?
        .to_owned();
    let url = Url::parse(&url).map_err(|_| AcmeErrors::ConversionError)?;
    let body: Value = response.json().await?;
    let authorizations = fetch_authorizations(&body.clone())?;

    let identifiers: Vec<String> = body.clone()["identifiers"]
        .as_array()
        .ok_or(AcmeErrors::ConversionError)?
        .iter()
        .map(|x| {
            x["value"]
                .as_str()
                .ok_or(AcmeErrors::ConversionError)
                .map(|val| val.to_string())
        })
        .collect::<Result<_, _>>()?;
    let finalize_url = body.clone()["finalize"]
        .as_str()
        .ok_or(AcmeErrors::ConversionError)?
        .to_string();
    let finalize_url = Url::parse(&finalize_url).map_err(|_| AcmeErrors::ConversionError)?;
    let body_cloned = body.clone();
    let status_str = body_cloned["status"]
        .as_str()
        .ok_or(AcmeErrors::ConversionError)?;

    let status = OrderStatus::from(status_str);
    Ok(Order {
        url,
        finalize_url,
        authorizations,
        identifiers,
        status,
        certificate: None,
    })
}
pub(crate) async fn perform_dns_01_challange(
    tokens: Vec<Token>,
    ec_key_pair: EcKeyPair,
    api_token: &str,
    zone_id: &str,
) -> Result<(), AcmeErrors> {
    for token in tokens {
        let encoded_digest = get_key_authorization(&token.token.clone(), &ec_key_pair.clone())?;
        post_dns_record(encoded_digest.clone(), &token.domain, api_token, zone_id).await?;
    }
    // Post the DNS record
    tracing::trace!("DNS record posted, waiting for the DNS changes to propagate...");
    // Wait for the DNS changes to propagate
    for i in 1..8 {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        tracing::trace!(
            "Waiting for DNS changes to propagate... time passed: {} seconds",
            i * 10
        );
    }
    tracing::trace!("DNS changes should have propagated by now");
    Ok(())
}
pub(crate) fn fetch_authorizations(response: &Value) -> Result<Vec<String>, AcmeErrors> {
    let authorizations: Result<Vec<String>, AcmeErrors> = response["authorizations"]
        .as_array()
        .ok_or(AcmeErrors::ConversionError)?
        .iter()
        .map(|authz| {
            authz
                .as_str()
                .ok_or(AcmeErrors::ConversionError)
                .map(ToString::to_string)
        })
        .collect();
    authorizations
}
pub(crate) async fn choose_challanges(
    authorizations: Vec<String>,
    challange_type: ChallangeType,
) -> Result<Vec<Challange>, AcmeErrors> {
    let client = Client::new();
    let mut challanges: Vec<Challange> = Vec::new();
    for authz in authorizations {
        let response = client.get(authz).send().await?;
        let authz = response.json::<Value>().await?;
        let challange = authz["challenges"]
            .as_array()
            .ok_or(AcmeErrors::ConversionError)?
            .iter()
            .find(|challange| challange["type"] == challange_type.to_string())
            .ok_or(AcmeErrors::ChallangeNotFound)?;
        let domain = authz["identifier"]["value"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_string();
        let url_str = challange["url"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?;
        let url = Url::parse(url_str).map_err(|_| AcmeErrors::ConversionError)?;
        challanges.push(Challange { url, domain });
    }
    Ok(challanges)
}
pub(crate) async fn get_challanges_tokens(
    challanges: Vec<Challange>,
) -> Result<Vec<Token>, AcmeErrors> {
    let client = Client::new();
    let mut details: Vec<Token> = Vec::new();
    for challange in challanges {
        let response = client.get(challange.url).send().await?;
        let detail = response.json::<Value>().await?;
        let token = detail["token"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_string();
        details.push(Token {
            domain: challange.domain,
            token,
        });
    }
    Ok(details)
}
pub(crate) async fn respond_to_challange(
    challange_url: Url,
    ec_key_pair: EcKeyPair,
    kid: Url,
) -> Result<Response, AcmeErrors> {
    let client = Client::new();
    let payload = JwtPayload::new();
    let nonce = new_nonce(&client, challange_url.clone()).await?;
    let body = create_jws(
        &nonce,
        &payload,
        challange_url.clone(),
        &ec_key_pair,
        Some(kid),
    )?;
    post(&client, challange_url, body).await
}

pub(crate) async fn finalize_order(
    csr: String,
    urls: DirectoryUrls,
    ec_key_pair: EcKeyPair,
    kid: Url,
    finalization_url: Url,
) -> Result<Response, AcmeErrors> {
    let client = Client::new();
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(&client, urls.clone().new_nonce).await?;
    let _ = payload.set_claim("csr", Some(serde_json::Value::String(csr)));
    let body = create_jws(
        &nonce,
        &payload,
        finalization_url.clone(),
        &ec_key_pair,
        Some(kid),
    )?;
    post(&client, finalization_url, body).await
}
#[cfg(test)]
mod tests {
    use std::{str::FromStr, vec};

    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    #[tokio::test]
    async fn test_new_directory() -> Result<(), AcmeErrors> {
        let urls = new_directory(&Url::from_str(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )?)
        .await?;
        assert_eq!(
            urls.new_account,
            Url::parse("https://acme-staging-v02.api.letsencrypt.org/acme/new-acct")?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_new_nonce() -> Result<(), AcmeErrors> {
        let client = Client::new();
        let urls = new_directory(&Url::from_str(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )?)
        .await?;
        let nonce = new_nonce(&client, urls.new_nonce).await;
        println!("{:?}", nonce);
        Ok(())
    }
    #[tokio::test]
    async fn test_new_account() -> Result<(), AcmeErrors> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory(&Url::from_str(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )?)
        .await?;
        let account = new_account(
            &client,
            urls,
            vec!["mateo@gmail.com".to_string()],
            ec_key_pair,
        )
        .await?;
        println!("{:?}", account);
        Ok(())
    }
    #[tokio::test]
    async fn test_submit_order() -> Result<(), AcmeErrors> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory(&Url::from_str(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )?)
        .await?;
        let account = new_account(
            &client,
            urls.clone(),
            vec!["mateo@gmail.com".to_string(), "mateo@sdfds.com".to_string()],
            ec_key_pair,
        )
        .await?;
        let order = submit_order(
            &client,
            urls,
            vec!["mateo.com"],
            account.account_key,
            account.account_url,
        )
        .await?;
        println!("{:?}", order);
        Ok(())
    }
}
