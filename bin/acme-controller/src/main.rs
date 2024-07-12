use acme_controller::CliInput;
use lib_acme::cert::{
    cert_manager::{issue_certificate, read_cert, renew_certificate},
    errors::AcmeErrors,
};
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
#[tokio::main]
async fn main() -> Result<(), AcmeErrors> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let args = CliInput::new();
    let domain_identifiers: Vec<&str> = args.domain_identifiers();
    let contact_mails: Vec<String> = args.contact_mails.clone();
    let challange_type = lib_acme::cert::types::ChallangeType::Dns01;
    let api_token: &str = args.api_token.as_str();
    let zone_id: &str = args.zone_id.as_str();
    let path = Path::new(&args.cert_path);
    let dir_url: &Url = &args.url;
    let renewal_threshold = args.renewal_threshold;
    issue_certificate(
        contact_mails.clone(),
        domain_identifiers.clone(),
        challange_type.clone(),
        api_token,
        zone_id,
        dir_url,
        path,
    )
    .await?;
    let cert = read_cert(path)?;
    renew_certificate(
        contact_mails,
        domain_identifiers,
        challange_type,
        api_token,
        zone_id,
        dir_url,
        &cert,
        path,
        renewal_threshold,
    )
    .await?;
    Ok(())
}
