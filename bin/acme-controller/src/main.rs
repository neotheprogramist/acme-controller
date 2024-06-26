use acme_controller::CliInput;
use lib_acme::cert::{cert_menager::issue_cerificate, errors::AcmeErrors};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
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
    let identifiers: Vec<&str> = args.identifiers();
    let contact_mail: Vec<String> = args.contact_mail.clone();
    let challange_type: &str = args.challange_type.as_str();
    let challange_type = lib_acme::cert::types::ChallangeType::from(challange_type);
    let api_token: &str = args.api_token.as_str();
    let zone_id: &str = args.zone_id.as_str();
    let dir_url: &str = match args.environment {
        lib_acme::cert::types::Environment::Staging => args.staging_directory_url.as_ref().unwrap(),
        lib_acme::cert::types::Environment::Production => args.directory_url.as_ref().unwrap(),
    };
    issue_cerificate(
        contact_mail,
        identifiers,
        challange_type,
        api_token,
        zone_id,
        dir_url
    )
    .await?;

    Ok(())
}
