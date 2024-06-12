use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
use serde::Serialize;
use serde_json::Value;
use url::Url;
extern crate tracing;
use super::cert_menager::fetch_authorizations;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::types::{AccountCredentials, Order, OrderStatus};
use super::{create_jws::create_jws, types::DirectoryUrls};
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

pub(crate) async fn new_directory(dir_url: &str) -> Result<DirectoryUrls, AcmeErrors> {
    let client = Client::new();
    let response = client.get(dir_url).send().await?;
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

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    #[tokio::test]
    async fn test_new_directory() -> Result<(), AcmeErrors> {
        let urls = new_directory("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
        assert_eq!(
            urls.new_account,
            Url::parse("https://acme-staging-v02.api.letsencrypt.org/acme/new-acct")?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_new_nonce() -> Result<(), AcmeErrors> {
        let client = Client::new();
        let urls = new_directory("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
        let nonce = new_nonce(&client, urls.new_nonce).await;
        println!("{:?}", nonce);
        Ok(())
    }
    #[tokio::test]
    async fn test_new_account() -> Result<(), AcmeErrors> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
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
        let urls = new_directory("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
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
