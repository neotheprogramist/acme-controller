use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
extern crate tracing;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::{create_jws::create_jws, types::DirectoryUrls};
const REPLAY_NONCE: &str = "replay-nonce";

pub(crate) async fn new_directory() -> Result<DirectoryUrls, AcmeErrors> {
    let client = Client::new();
    let directory_url = "https://acme-v02.api.letsencrypt.org/directory";
    let response = client.get(directory_url).send().await?;
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
) -> Result<String, AcmeErrors> {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.new_nonce).await?;
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
    let response = post(client, urls.new_account, body).await?;
    let account_url = response
        .headers()
        .get("location")
        .ok_or(AcmeErrors::MissingLocationHeader)?
        .to_str()?
        .to_owned();
    Ok(account_url)
}

pub(crate) async fn submit_order(
    client: &Client,
    urls: DirectoryUrls,
    identifiers: Vec<&str>,
    ec_key_pair: EcKeyPair,
    kid: String,
) -> Result<Response, AcmeErrors> {
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
    post(client, urls.new_order, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    #[tokio::test]
    async fn test_new_directory() -> Result<(), AcmeErrors> {
        let urls = new_directory().await?;
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
        let urls = new_directory().await?;
        let nonce = new_nonce(&client, urls.new_nonce).await;
        println!("{:?}", nonce);
        Ok(())
    }
    #[tokio::test]
    async fn test_new_account() -> Result<(), AcmeErrors> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory().await?;
        let response = new_account(&client, urls, "mateo@gmail.com".to_string(), ec_key_pair).await;
        println!("{:?}", response);
        Ok(())
    }
}
