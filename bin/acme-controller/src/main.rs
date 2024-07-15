use acme_controller::CliInput;
use acme_controller::init_logging;
use lib_acme::cert::types::ChallangeType;
use lib_acme::cert::{cert_manager::CertificateManager, errors::AcmeErrors};

#[tokio::main]
async fn main() -> Result<(), AcmeErrors> {
    init_logging();

    let args = CliInput::new();

    let manager = CertificateManager::new(
        args.contact_mails.clone(),
        args.domain_identifiers,
        ChallangeType::Dns01,
        args.api_token,
        args.zone_id,
        args.url,  
        args.renewal_threshold,
    );
    manager.issue_certificate().await?;

    Ok(())
}
