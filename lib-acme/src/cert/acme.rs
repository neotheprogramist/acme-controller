use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::Client;
use serde_json::Value;
extern crate tracing;
use super::http_request::post;
use super::{create_jws::create_jws, types::DirectoryUrls};

const REPLAY_NONCE: &str = "replay-nonce";

pub async fn new_directory() -> DirectoryUrls {
    let client = Client::new();
    let directory_url = "https://acme-v02.api.letsencrypt.org/directory.";
    let response = client.get(directory_url).send().await.unwrap();
    let dir: Value = response.json().await.unwrap();

    DirectoryUrls {
        new_nonce: dir["newNonce"].as_str().unwrap().to_string(), // Extract as str and convert to String
        new_account: dir["newAccount"].as_str().unwrap().to_string(),
        new_order: dir["newOrder"].as_str().unwrap().to_string(),
        new_authz: dir["newAuthz"].as_str().map(String::from), // Map to convert Option<&str> to Option<String>
        revoke_cert: dir["revokeCert"].as_str().map(String::from),
        key_change: dir["keyChange"].as_str().map(String::from),
    }
}
pub async fn new_nonce(client: &Client, url_value: String) -> String {
    let response = client.head(url_value).send().await.unwrap();
    let nonce = response
        .headers()
        .get(REPLAY_NONCE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    nonce
}
pub async fn new_account(
    client: &Client,
    urls: DirectoryUrls,
    contact_mail: String,
    ec_key_pair: EcKeyPair,
) -> String {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.clone().new_nonce).await;
    let _ = payload.set_claim("termsOfServiceAgreed", Some(serde_json::Value::Bool(true)));
    let _ = payload.set_claim(
        "contact",
        Some(serde_json::Value::Array(vec![serde_json::Value::String(
            format!("mailto:{}", contact_mail),
        )])),
    );
    let body = create_jws(nonce, payload, urls.new_account.clone(), ec_key_pair, None).unwrap();
    let response = post(client, urls.new_account, body).await;
    let account_url = response
        .headers()
        .get("location")
        .ok_or("Location header missing")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    account_url
}

pub async fn submit_order(
    client: &Client,
    urls: DirectoryUrls,
    identifiers: Vec<&str>,
    ec_key_pair: EcKeyPair,
    kid: String,
) -> reqwest::Response {
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(client, urls.clone().new_nonce).await;
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
        nonce,
        payload,
        urls.new_order.clone(),
        ec_key_pair,
        Some(kid),
    )
    .unwrap();
    post(client, urls.new_order, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
    #[tokio::test]
    async fn test_new_directory() -> Result<(), Box<dyn std::error::Error>> {
        let urls = new_directory().await;
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
    async fn test_new_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let urls = new_directory().await;
        let nonce = new_nonce(&client, urls.new_nonce).await;
        println!("{:?}", nonce);
        Ok(())
    }
    #[tokio::test]
    async fn test_new_account() -> Result<(), Box<dyn std::error::Error>> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory().await;
        let response = new_account(&client, urls, "mateo@gmail.com".to_string(), ec_key_pair).await;
        println!("{:?}", response);
        Ok(())
    }
}
