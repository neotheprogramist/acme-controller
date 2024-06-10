use josekit::jwk::alg::ec::EcCurve;
use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
use serde_json::Value;
use std::fs::File;
use std::io::Write;

extern crate tracing;
use crate::cert::acme::{new_account, new_directory, submit_order};
use crate::cert::crypto::{generate_csr, get_key_authorization};
use crate::cert::dns_menagment::{delete_dns_record, post_dns_record};
use crate::cert::types::{ChallangeType, OrderStatus};

use super::acme::new_nonce;
use super::http_request::post;
use super::{create_jws::create_jws, types::DirectoryUrls};

pub async fn dns_01_challange(
    tokens: Vec<(String, String)>,
    ec_key_pair: EcKeyPair,
    api_token: &str,
    zone_id: &str,
) {
    for token in tokens {
        let encoded_digest = get_key_authorization(token.1.clone(), ec_key_pair.clone());
        post_dns_record(encoded_digest.clone(), &token.0, api_token, zone_id).await;
    }
    // Post the DNS record
    tracing::trace!("DNS record posted, waiting for the DNS changes to propagate...");
    // Wait for the DNS changes to propagate
    for i in 1..8 {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        tracing::trace!(
            "Waiting for DNS changes to propagate... time passed :{} seconds",
            i * 10
        );
    }
    tracing::trace!("DNS changes should have propagated by now");
}
pub async fn fetch_authorizations(response: Value) -> Vec<String> {
    let order = response;
    let authorizations: Vec<String> = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|authz| authz.as_str().unwrap().to_string())
        .collect();
    authorizations
}
pub async fn choose_challanges(
    authorizations: Vec<String>,
    challange_type: ChallangeType,
) -> Vec<(String, String)> {
    let client = Client::new();
    let mut challanges: Vec<(String, String)> = Vec::new();
    for authz in authorizations {
        let response = client.get(authz).send().await.unwrap();
        let authz = response.json::<Value>().await.unwrap();
        let challange = authz["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|challange| challange["type"] == challange_type.to_string())
            .unwrap();
        let domain = authz["identifier"]["value"].as_str().unwrap().to_string();
        let challange = challange["url"].as_str().unwrap().to_string();
        challanges.push((challange, domain));
    }
    challanges
}
pub async fn get_challanges_tokens(challanges: Vec<(String, String)>) -> Vec<(String, String)> {
    let client = Client::new();
    let mut details: Vec<(String, String)> = Vec::new();
    for challange in challanges {
        let response = client.get(challange.0).send().await.unwrap();
        let detail = response.json::<Value>().await.unwrap();
        details.push((challange.1, detail["token"].as_str().unwrap().to_string()));
    }
    details
}
pub async fn respond_to_challange(
    challange_url: String,
    ec_key_pair: EcKeyPair,
    kid: String,
) -> Response {
    let client = Client::new();
    let payload = JwtPayload::new();
    let nonce = new_nonce(&client, challange_url.clone()).await;
    let body = create_jws(
        nonce,
        payload,
        challange_url.clone(),
        ec_key_pair,
        Some(kid),
    )
    .unwrap();
    post(&client, challange_url, body).await
}

pub async fn fetch_order_status(client: &Client, order_url: &str) -> Result<Value, reqwest::Error> {
    let response = client.get(order_url).send().await?;
    response.json::<Value>().await
}

pub async fn order_finalization(
    csr: String,
    urls: DirectoryUrls,
    ec_key_pair: EcKeyPair,
    kid: String,
    finalization_url: String,
) -> Response {
    let client = Client::new();
    let mut payload = JwtPayload::new();
    let nonce = new_nonce(&client, urls.clone().new_nonce).await;
    let _ = payload.set_claim("csr", Some(serde_json::Value::String(csr)));
    let body = create_jws(
        nonce,
        payload,
        finalization_url.clone(),
        ec_key_pair,
        Some(kid),
    )
    .unwrap();
    post(&client, finalization_url, body).await
}

pub async fn certificate_procedure(
    contact_mail: String,
    identifiers: Vec<&str>,
    challange_type: ChallangeType,
    api_token: &str,
    zone_id: &str,
) {
    let ec_key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let client = Client::new();
    let urls = new_directory().await;

    let account_url = new_account(
        &client,
        urls.clone(),
        contact_mail.clone(),
        ec_key_pair.clone(),
    )
    .await;

    let order = submit_order(
        &client,
        urls.clone(),
        identifiers.clone(),
        ec_key_pair.clone(),
        account_url.to_string(),
    )
    .await;

    let order_url = order
        .headers()
        .get("location")
        .ok_or("Location header missing")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned(); // Make an owned copy of the URL

    tracing::trace!("Order URL: {}", order_url);
    // Deserialize the JSON body for further processing
    let order_body: Value = order.json().await.unwrap();

    // Now that we have both `order_url` and `order_body`, we no longer need the original `order`
    let authorizations = fetch_authorizations(order_body).await;
    let challanges = choose_challanges(authorizations, challange_type.clone()).await;

    let tokens = get_challanges_tokens(challanges.clone()).await;
    // processing dns-01 challenges
    if challange_type == ChallangeType::Dns01 {
        dns_01_challange(tokens, ec_key_pair.clone(), api_token, zone_id).await;
    }
    // Respond to the challenges
    for challange in challanges.clone() {
        respond_to_challange(
            challange.0.clone(),
            ec_key_pair.clone(),
            account_url.to_string().clone(),
        )
        .await;
    }
    tracing::trace!("Challenge responded to, waiting for the order to complete...");
    loop {
        let order_status = fetch_order_status(&client, &order_url).await.unwrap();
        let status_str = order_status["status"].as_str().unwrap_or("unknown");
        let status = OrderStatus::from(status_str);

        match status {
            OrderStatus::Valid => {
                tracing::trace!("Order is completed successfully. Downloading certificate...");
                let certificate_url = order_status["certificate"].as_str().unwrap();
                tracing::trace!("Certificate URL: {}", certificate_url);
                let certificate = client.get(certificate_url).send().await.unwrap();
                let certificate_body = certificate.text().await.unwrap();
                // Define the path to save the certificate
                let path = "certificate.pem"; // Adjust the path as necessary
                                              // Write to a file
                let mut file = File::create(path).unwrap();
                file.write_all(certificate_body.as_bytes()).unwrap();
                tracing::trace!("Certificate saved to {}", path);
                for id in identifiers.clone() {
                    delete_dns_record(api_token, zone_id, id).await;
                }
                break;
            }
            OrderStatus::Invalid => {
                tracing::trace!("Order has failed.");
                break;
            }
            OrderStatus::Pending => {
                tracing::trace!("Order is pending...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            OrderStatus::Ready => {
                tracing::trace!("Order is ready... finalizing.");
                let finalization_url = order_status["finalize"].as_str().unwrap();
                let csr = generate_csr(identifiers.clone()).unwrap();
                let _response = order_finalization(
                    csr,
                    urls.clone(),
                    ec_key_pair.clone(),
                    account_url.to_string(),
                    finalization_url.to_string(),
                )
                .await;
            }
            OrderStatus::Processing => {
                tracing::trace!("Order is processing...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            OrderStatus::Unknown => {
                tracing::trace!("Order status: {:?}", status);
                break;
            }
        }
    }
}
