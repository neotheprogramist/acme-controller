use std::io::{Read, Write};
use std::path::Path;
use josekit::jwk::alg::ec::EcCurve;
use josekit::{jwk::alg::ec::EcKeyPair, jwt::JwtPayload};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::X509;
use reqwest::{Client, Response};
use serde_json::Value;
use tokio::time;
use url::Url;
extern crate tracing;
use crate::cert::acme::{new_account, new_directory, submit_order};
use crate::cert::crypto::{generate_csr, get_key_authorization};
use crate::cert::dns_menagment::{delete_dns_record, post_dns_record};
use crate::cert::types::{ChallangeType, OrderStatus};

use super::acme::new_nonce;
use super::errors::AcmeErrors;
use super::http_request::post;
use super::types::{Challange, Token};
use super::{create_jws::create_jws, types::DirectoryUrls};

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
    contact_mail: Vec<String>,
    identifiers: Vec<&str>,
    challange_type: ChallangeType,
    api_token: &str,
    zone_id: &str,
    dir_url: &str,
    path: &Path,
) -> Result<(), AcmeErrors> {
    let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
    let client = Client::new();
    let urls = new_directory(dir_url).await?;

    let account = new_account(
        &client,
        urls.clone(),
        contact_mail.clone(),
        ec_key_pair.clone(),
    )
    .await?;

    let mut order = submit_order(
        &client,
        urls.clone(),
        identifiers.clone(),
        ec_key_pair.clone(),
        account.account_url.clone(),
    )
    .await?;

    tracing::trace!("Order URL: {}", order.url.clone());

    let challanges =
        choose_challanges(order.authorizations.clone(), challange_type.clone()).await?;

    let tokens = get_challanges_tokens(challanges.clone()).await?;
    // processing dns-01 challenges
    if challange_type == ChallangeType::Dns01 {
        perform_dns_01_challange(tokens, ec_key_pair.clone(), api_token, zone_id).await?;
    }
    // Respond to the challenges
    for challange in challanges.clone() {
        respond_to_challange(
            challange.url.clone(),
            ec_key_pair.clone(),
            account.account_url.clone(),
        )
        .await?;
    }
    tracing::trace!("Challenge responded to, waiting for the order to complete...");
    loop {
        order.update_status().await?;
        let status = order.status.clone();
        match status {
            OrderStatus::Valid => {
                tracing::trace!("Order is completed successfully. Downloading certificate...");
                let certificate_url = order
                    .certificate
                    .clone()
                    .ok_or(AcmeErrors::ConversionError)?;
                tracing::trace!("Certificate URL: {}", certificate_url);
                let certificate = client.get(certificate_url).send().await?;
                let certificate_body = certificate.text().await?;
                let certificate = X509::from_pem(certificate_body.as_bytes())?;
                save_cert(&certificate, path)?;
                for id in order.identifiers.clone() {
                    delete_dns_record(api_token, zone_id, &id).await?;
                }
                break;
            }
            OrderStatus::Invalid => {
                tracing::trace!("Order has failed.");
                Err(AcmeErrors::OrderError)?;
            }
            OrderStatus::Pending => {
                tracing::trace!("Order is pending...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            OrderStatus::Ready => {
                tracing::trace!("Order is ready... finalizing.");
                let finalization_url = order.finalize_url.clone();
                let csr = generate_csr(identifiers.clone())?;
                let _response = finalize_order(
                    csr,
                    urls.clone(),
                    account.account_key.clone(),
                    account.account_url.clone(),
                    finalization_url,
                )
                .await;
            }
            OrderStatus::Processing => {
                tracing::trace!("Order is processing...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            OrderStatus::Unknown => {
                tracing::trace!("Order status: {:?}", status);
                Err(AcmeErrors::OrderError)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn get_certificate_expiration(cert: &X509) -> Result<&Asn1TimeRef, AcmeErrors> {
    let expiration_date: &Asn1TimeRef = cert.not_after();
    return Ok(expiration_date);
}

/// Saves an X509 certificate to a specified file path.
///
/// # Arguments
///
/// * `cert` - A reference to the X509 certificate to be saved.
/// * `path` - A reference to the file path where the certificate should be saved.
///
/// # Errors
///
/// This function will return an error of type `AcmeErrors` in the following cases:
///
/// * If there is an issue creating the file at the specified path.
/// * If there is an issue writing the certificate data to the file.
///
///


pub fn save_cert(cert: &X509, path: &Path) -> Result<(), AcmeErrors> {
    // Save the certificate to a file
    let mut file = std::fs::File::create(path)?;
    file.write_all(cert.to_pem().unwrap().as_slice())?;
    Ok(())
}


/// Reads an X509 certificate from a specified file path.
///
/// # Arguments
///
/// * `path` - A reference to the file path from which the certificate should be read.
///
/// # Returns
///
/// This function returns a `Result`:
///
/// * `Ok(X509)` - If the certificate is successfully read from the specified file.
/// * `Err(AcmeErrors)` - An error of type `AcmeErrors` if the certificate cannot be read.
///
/// # Errors
///
/// This function will return an error of type `AcmeErrors` in the following cases:
///
/// * If there is an issue opening the file at the specified path.
/// * If there is an issue reading the certificate data from the file.
/// * If the certificate data is not valid PEM-encoded X509 data.
///
/// 
/// 
pub fn read_cert(path: &Path) -> Result<X509, AcmeErrors> {
    // Read the certificate from a file
    let mut file = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(X509::from_pem(&buffer)?)
}

/// Asynchronously renews a certificate based on provided contact email, identifiers, and other parameters.
///
/// This function continuously checks the expiration date of the given certificate and renews it if the expiration date
/// is within 30 days. Upon renewal, the new certificate is saved to the specified path.
///
/// # Arguments
///
/// * `contact_mail` - A vector of contact email addresses for certificate renewal notifications.
/// * `identifiers` - A vector of identifiers (e.g., domain names) for which the certificate is issued.
/// * `challange_type` - The type of challenge used for certificate validation.
/// * `api_token` - The API token used for authentication with the certificate authority.
/// * `zone_id` - The zone identifier used in DNS challenges.
/// * `dir_url` - The directory URL for the ACME server.
/// * `cert` - A reference to the current X509 certificate.
/// * `path` - A reference to the path where the renewed certificate should be saved.
///
/// # Returns
///
/// This function returns a `Result`:
///
/// * `Ok(())` - If the certificate is successfully renewed and saved.
/// * `Err(AcmeErrors)` - An error of type `AcmeErrors` if the certificate cannot be renewed or saved.
///
/// # Errors
///
/// This function will return an error of type `AcmeErrors` in the following cases:
///
/// * If there is an issue issuing the certificate.
/// * If there is an issue retrieving the certificate's expiration date.
/// * If there is an issue determining the current date.
/// * If there is an issue saving the renewed certificate.

pub async fn renew_certificate(
    contact_mail: Vec<String>,
    identifiers: Vec<&str>,
    challange_type: ChallangeType,
    api_token: &str,
    zone_id: &str,
    dir_url: &str,
    cert: &X509,
    path: &Path,
) -> Result<(), AcmeErrors> {
    let mut interval = time::interval(time::Duration::from_secs(60*60*12));
    loop {
        interval.tick().await;
        tracing::trace!("Checking certificate expiration date...");
        let expiration_date = get_certificate_expiration(&cert)?;
        tracing::trace!("Certificate expiration date: {:?}", expiration_date);
        let now = Asn1Time::days_from_now(0)?;
        if now.diff(&expiration_date)?.days > 30 {
            tracing::trace!("Certificate is still valid.");
            continue;
        } else {
            tracing::trace!("Certificate is about to expire. Renewing certificate...");
            issue_cerificate(
                contact_mail.clone(),
                identifiers.clone(),
                challange_type.clone(),
                api_token,
                zone_id,
                dir_url,
                path,
            )
            .await?;
            save_cert(cert, path)?;
        }
    }
}
