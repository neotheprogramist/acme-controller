use josekit::jwk::alg::ec::EcCurve;
use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use reqwest::{Client, Response};
use serde_json::Value;
extern crate tracing;
use crate::cert::acme::{new_account, new_directory, submit_order};
use crate::cert::crypto::{generate_csr, get_key_authorization};
use crate::cert::dns_menagment::{delete_dns_record, post_dns_record};
use crate::cert::types::{ChallangeType, OrderStatus};

use super::acme::new_nonce;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::{create_jws::create_jws, types::DirectoryUrls};

pub(crate) async fn perform_dns_01_challange(
    tokens: Vec<(String, String)>,
    ec_key_pair: EcKeyPair,
    api_token: &str,
    zone_id: &str,
) -> Result<(), AcmeErrors> {
    for token in tokens {
        let encoded_digest = get_key_authorization(&token.1.clone(), &ec_key_pair.clone())?;
        post_dns_record(encoded_digest.clone(), &token.0, api_token, zone_id).await?;
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
) -> Result<Vec<(String, String)>, AcmeErrors> {
    let client = Client::new();
    let mut challanges: Vec<(String, String)> = Vec::new();
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
        let challange = challange["url"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_string();
        challanges.push((challange, domain));
    }
    Ok(challanges)
}
pub(crate) async fn get_challanges_tokens(
    challanges: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, AcmeErrors> {
    let client = Client::new();
    let mut details: Vec<(String, String)> = Vec::new();
    for challange in challanges {
        let response = client.get(challange.0).send().await?;
        let detail = response.json::<Value>().await?;
        details.push((
            challange.1,
            detail["token"]
                .as_str()
                .ok_or(AcmeErrors::ConversionError)?
                .to_string(),
        ));
    }
    Ok(details)
}
pub(crate) async fn respond_to_challange(
    challange_url: String,
    ec_key_pair: EcKeyPair,
    kid: String,
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

pub(crate) async fn fetch_order_status(
    client: &Client,
    order_url: &str,
) -> Result<Value, reqwest::Error> {
    let response = client.get(order_url).send().await?;
    response.json::<Value>().await
}

pub(crate) async fn finalize_order(
    csr: String,
    urls: DirectoryUrls,
    ec_key_pair: EcKeyPair,
    kid: String,
    finalization_url: String,
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
/// Completes the entire certificate provisioning process using the ACME protocol.
/// This function performs multiple steps: it creates an account, submits a certificate order,
/// handles domain validation challenges, and retrieves the issued certificate.
///
/// # Parameters
/// - `contact_mail`: The contact email address used for the ACME account registration.
/// - `identifiers`: A list of domain names (identifiers) for which the certificate should be issued.
/// - `challange_type`: The type of ACME challenge to perform for domain validation (e.g., DNS-01).
/// - `api_token`: API token used for DNS provider to create and delete DNS records.
/// - `zone_id`: The DNS zone identifier used for creating DNS records.
///
/// # Returns
/// Returns a `Result<(), AcmeErrors>` indicating the success or failure of the certificate provisioning process.
/// On success, it ensures that the certificate has been properly issued and handled.
///
/// # Errors
/// This function can return `AcmeErrors` which encapsulates several types of errors:
/// - `RequestFailed`: Errors that occur during HTTP requests to the ACME server.
/// - `MissingLocationHeader`: If the HTTP response from the ACME server is missing expected headers.
/// - `ConversionError`: Issues with data type conversions, typically when parsing server responses.
/// - `MissingNonce`: If a required nonce is missing during the ACME request process.
/// - `ChallengeNotFound`: If the specified type of challenge is not found in the authorization details.
/// - Any other errors as defined in `AcmeErrors` that may occur during the process.

pub async fn issue_cerificate(
    contact_mail: String,
    identifiers: Vec<&str>,
    challange_type: ChallangeType,
    api_token: &str,
    zone_id: &str,
) -> Result<(), AcmeErrors> {
    let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
    let client = Client::new();
    let urls = new_directory().await?;

    let account_url = new_account(
        &client,
        urls.clone(),
        contact_mail.clone(),
        ec_key_pair.clone(),
    )
    .await?;

    let order = submit_order(
        &client,
        urls.clone(),
        identifiers.clone(),
        ec_key_pair.clone(),
        account_url.to_string(),
    )
    .await?;

    let order_url = order
        .headers()
        .get("location")
        .ok_or(AcmeErrors::MissingLocationHeader)?
        .to_str()?
        .to_owned(); // Make an owned copy of the URL

    tracing::trace!("Order URL: {}", order_url);
    // Deserialize the JSON body for further processing
    let order_body: Value = order.json().await?;

    // Now that we have both `order_url` and `order_body`, we no longer need the original `order`
    let authorizations = fetch_authorizations(&order_body)?;
    let challanges = choose_challanges(authorizations, challange_type.clone()).await?;

    let tokens = get_challanges_tokens(challanges.clone()).await?;
    // processing dns-01 challenges
    if challange_type == ChallangeType::Dns01 {
        perform_dns_01_challange(tokens, ec_key_pair.clone(), api_token, zone_id).await?;
    }
    // Respond to the challenges
    for challange in challanges.clone() {
        respond_to_challange(
            challange.0.clone(),
            ec_key_pair.clone(),
            account_url.to_string().clone(),
        )
        .await?;
    }
    tracing::trace!("Challenge responded to, waiting for the order to complete...");
    loop {
        let order_status = fetch_order_status(&client, &order_url).await?;
        let status_str = order_status["status"]
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?;
        let status = OrderStatus::from(status_str);

        match status {
            OrderStatus::Valid => {
                tracing::trace!("Order is completed successfully. Downloading certificate...");
                let certificate_url = order_status["certificate"]
                    .as_str()
                    .ok_or(AcmeErrors::ConversionError)?;
                tracing::trace!("Certificate URL: {}", certificate_url);
                let certificate = client.get(certificate_url).send().await?;
                let certificate_body = certificate.text().await?;
                println!("{certificate_body}");
                for id in identifiers.clone() {
                    delete_dns_record(api_token, zone_id, id).await?;
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
                let finalization_url = order_status["finalize"]
                    .as_str()
                    .ok_or(AcmeErrors::ConversionError)?
                    .to_string();
                let csr = generate_csr(identifiers.clone())?;
                let _response = finalize_order(
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
    Ok(())
}
