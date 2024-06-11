use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
use serde_json::Value;
extern crate tracing;
use super::cert_menager::fetch_authorizations;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::types::{AccountCredentials, Order, OrderStatus};
use super::{create_jws::create_jws, types::DirectoryUrls};
const REPLAY_NONCE: &str = "replay-nonce";

pub(crate) async fn new_directory(dir_url: &str) -> Result<DirectoryUrls, AcmeErrors> {
    let client = Client::new();
    let response = client.get(dir_url).send().await?;
    Ok(response.json().await?)
}

pub(crate) async fn new_nonce(client: &Client, url_value: String) -> Result<String, AcmeErrors> {
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
    contact_mail: String,
    ec_key_pair: EcKeyPair,
) -> Result<AccountCredentials, AcmeErrors> {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.new_nonce.clone()).await?;
    let _ = payload.set_claim("termsOfServiceAgreed", Some(serde_json::Value::Bool(true)));
    let _ = payload.set_claim(
        "contact",
        Some(serde_json::Value::Array(vec![serde_json::Value::String(
            format!("mailto:{contact_mail}"),
        )])),
    );
    let body = create_jws(
        &nonce,
        &payload,
        urls.new_account.clone(),
        &ec_key_pair,
        None,
    )?;
    let response = post(client, urls.new_account.clone(), body).await?;
    if response.status().as_u16() != 201 {
        Err(AcmeErrors::AccountError)}
    else{
        parse_account(response, ec_key_pair)
    }
}
pub(crate) fn parse_account(response: Response,ec_key_pair: EcKeyPair)->Result<AccountCredentials,AcmeErrors>{
    let account_url = response
        .headers()
        .get("location")
        .ok_or(AcmeErrors::MissingLocationHeader)?
        .to_str()?
        .to_owned();
    Ok(AccountCredentials {
        account_url,
        account_key: ec_key_pair,
    })
}

pub(crate) async fn submit_order(
    client: &Client,
    urls: DirectoryUrls,
    identifiers: Vec<&str>,
    ec_key_pair: EcKeyPair,
    kid: String,
) -> Result<Order, AcmeErrors> {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.clone().new_nonce).await?;
    let _ = payload.set_claim(
        "identifiers",
        Some(serde_json::Value::Array(
            identifiers
                .iter()
                .map(|x| {
                    serde_json::json!({
                        "type": "dns",
                        "value": x
                    })
                })
                .collect::<Vec<serde_json::Value>>(),
        )),
    );
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
    let body: Value = response.json().await?;
    let authorizations = fetch_authorizations(&body.clone())?;

    let identifiers = body.clone()["identifiers"]
        .as_array()
        .ok_or(AcmeErrors::ConversionError)?
        .iter()
        .map(|x| x["value"].as_str().unwrap().to_string())
        .collect();
    let finalize_url = body.clone()["finalize"]
        .as_str()
        .ok_or(AcmeErrors::ConversionError)?
        .to_string();
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
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    #[tokio::test]
    async fn test_new_directory() -> Result<(), AcmeErrors> {
        let urls = new_directory("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
        assert_eq!(
            urls.new_nonce,
            "https://acme-v02.api.letsencrypt.org/acme/new-nonce"
        );
        assert_eq!(
            urls.new_account,
            "https://acme-v02.api.letsencrypt.org/acme/new-acct"
        );
        assert_eq!(
            urls.new_order,
            "https://acme-v02.api.letsencrypt.org/acme/new-order"
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
        let account =
            new_account(&client, urls, "mateo@gmail.com".to_string(), ec_key_pair).await?;
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
            "mateo@gmail.com".to_string(),
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
