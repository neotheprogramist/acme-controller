use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::alg::ec::EcKeyPair;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::X509;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::time;
use url::Url;
extern crate tracing;
use super::errors::AcmeErrors;
use crate::cert::acme::{
    choose_challanges, finalize_order, get_challanges_tokens, new_account, new_directory,
    perform_dns_01_challange, respond_to_challange, submit_order,
};
use crate::cert::crypto::generate_csr;
use crate::cert::dns_menagment::delete_dns_record;
use crate::cert::types::{ChallangeType, OrderStatus};

#[derive(Clone)]
pub struct CertificateManager {
    contact_mails: Vec<String>,
    domain_identifiers: Vec<String>,
    challange_type: ChallangeType,
    api_token: String,
    zone_id: String,
    dir_url: Url,
    pub cert: Arc<Mutex<Option<X509>>>,
    pub ec_key_pair: Arc<Mutex<Option<EcKeyPair>>>,
    renewal_threshold: i32,
}
impl CertificateManager {
    /// Constructs a new `CertificateManager`.
    ///
    /// # Parameters
    /// * `contact_mails` - A list of email addresses for contact.
    /// * `domain_identifiers` - A list of domain names that the manager will handle.
    /// * `challenge_type` - The type of ACME challenge to use.
    /// * `api_token` - API token for DNS provider interactions.
    /// * `zone_id` - The identifier for the DNS zone.
    /// * `dir_url` - The ACME directory URL.
    /// * `renewal_threshold` - The number of days before expiration at which renewal should be attempted.
    pub fn new(
        contact_mails: Vec<String>,
        domain_identifiers: Vec<String>,
        challange_type: ChallangeType,
        api_token: String,
        zone_id: String,
        dir_url: Url,
        renewal_threshold: i32,
    ) -> Self {
        CertificateManager {
            contact_mails,
            domain_identifiers,
            challange_type,
            api_token,
            zone_id,
            dir_url,
            cert: Arc::new(Mutex::new(None)),
            ec_key_pair: Arc::new(Mutex::new(None)),
            renewal_threshold,
        }
    }
    /// Issues a new certificate using the ACME protocol.
    ///
    /// # Returns
    /// A `Result<(), AcmeErrors>` indicating success or an error during the certificate issuance process.
    pub async fn issue_certificate(&self) -> Result<(), AcmeErrors> {
        let ec_key_pair = EcKeyPair::generate(EcCurve::P256)?;
        let client = Client::new();
        let urls = new_directory(&self.dir_url).await?;

        let account = new_account(
            &client,
            urls.clone(),
            self.contact_mails.clone(),
            ec_key_pair.clone(),
        )
        .await?;

        let domain_identifiers: Vec<&str> =
            self.domain_identifiers.iter().map(|s| s.as_str()).collect();
        let mut order = submit_order(
            &client,
            urls.clone(),
            domain_identifiers,
            ec_key_pair.clone(),
            account.account_url.clone(),
        )
        .await?;

        tracing::trace!("Order URL: {}", order.url.clone());

        let challanges =
            choose_challanges(order.authorizations.clone(), self.challange_type.clone()).await?;

        let tokens = get_challanges_tokens(challanges.clone()).await?;
        // processing dns-01 challenges
        if self.challange_type == ChallangeType::Dns01 {
            perform_dns_01_challange(tokens, ec_key_pair.clone(), &self.api_token, &self.zone_id)
                .await?;
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
                    let mut cert_guard = self.cert.lock().map_err(|e| {
                        AcmeErrors::MutexPoisonedError(format!(
                            "Failed to acquire cert lock: {}",
                            e
                        ))
                    })?;
                    let mut key_pair_guard = self.ec_key_pair.lock().map_err(|e| {
                        AcmeErrors::MutexPoisonedError(format!(
                            "Failed to acquire key pair lock: {}",
                            e
                        ))
                    })?;
                    *cert_guard = Some(certificate);
                    *key_pair_guard = Some(ec_key_pair);
                    for id in order.identifiers.clone() {
                        delete_dns_record(&self.api_token, &self.zone_id, &id).await?;
                    }
                    break Ok(());
                }
                OrderStatus::Invalid => {
                    tracing::trace!("Order has failed.");
                    break Err(AcmeErrors::OrderError);
                }
                OrderStatus::Pending => {
                    tracing::trace!("Order is pending...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                OrderStatus::Ready => {
                    tracing::trace!("Order is ready... finalizing.");
                    let finalization_url = order.finalize_url.clone();
                    let csr =
                        generate_csr(self.domain_identifiers.iter().map(|s| s.as_str()).collect())?;
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
                    break Err(AcmeErrors::OrderError);
                }
            }
        }
    }
    // Renews the certificate when necessary, based on expiration checks.
    ///
    /// # Parameters
    /// * `tx` - A `watch::Sender` used to notify other components of the application about the renewal.
    ///
    /// # Returns
    /// A `Result<(), AcmeErrors>` indicating the success or failure of the renewal operation.
    pub async fn renew_certificate(&self, tx: watch::Sender<()>) -> Result<(), AcmeErrors> {
        let mut interval = time::interval(time::Duration::from_secs(60 * 60 * 12));
        loop {
            interval.tick().await;
            tracing::trace!("Checking certificate expiration date...");
            let cert = self
                .get_cert()?
                .ok_or(AcmeErrors::MutexPoisonedError(
                    "Failed to acquire cert lock".to_string(),
                ))?;
            let expiration_date = get_certificate_expiration(&cert)?;
            tracing::trace!("Certificate expiration date: {:?}", expiration_date);
            let now = Asn1Time::days_from_now(0)?;
            if now.diff(expiration_date)?.days > self.renewal_threshold {
                tracing::trace!("Certificate is still valid.");
                continue;
            } else {
                tracing::trace!("Certificate is about to expire. Renewing certificate...");
                self.issue_certificate().await?;
                tx.send(()).map_err(|e| {
                    AcmeErrors::ChannelError(format!("Failed to send watch signal: {}", e))
                })?;    
            }
        }
    }
    pub fn get_cert(&self) -> Result<Option<X509>,AcmeErrors> {
        let locked_cert = self.cert.lock().map_err(|e| {
            AcmeErrors::MutexPoisonedError(format!("Failed to acquire cert lock: {}", e))
        })?;
        Ok(locked_cert.as_ref().cloned())
    }
    pub fn get_key_pair(&self) -> Result<Option<EcKeyPair>,AcmeErrors> {
        let locked_key = self.ec_key_pair.lock().map_err(|e| {
            AcmeErrors::MutexPoisonedError(format!("Failed to acquire cert lock: {}", e))
        })?;
        Ok(locked_key.as_ref().cloned())
    }
}

pub(crate) fn get_certificate_expiration(cert: &X509) -> Result<&Asn1TimeRef, AcmeErrors> {
    let expiration_date: &Asn1TimeRef = cert.not_after();
    Ok(expiration_date)
}
