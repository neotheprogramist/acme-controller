use acme_controller::CliInput;
use clap::Parser;
use lib_acme::cert::cert_menager::certificate_procedure;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[tokio::main]
async fn main() {
    let args = CliInput::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let identifiers: Vec<&str> = args.identifiers.split(',').collect();
    let contact_mail: String = args.contact_mail;
    let challange_type: &str = args.challange_type.as_str();
    let challange_type = lib_acme::cert::types::ChallangeType::from(challange_type);
    let api_token: &str = args.api_token.as_str();
    let zone_id: &str = args.zone_id.as_str();
    certificate_procedure(
        contact_mail,
        identifiers,
        challange_type,
        api_token,
        zone_id,
    )
    .await;
}
