use clap::Parser;
use lib_acme::cert::types::Environment;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
pub struct CliInput {
    #[arg(short = 'i', long, env)]
    pub identifiers: Vec<String>,
    #[arg(short = 'm', long, env)]
    pub contact_mail: Vec<String>,
    #[arg(short = 'c', long, env)]
    pub challange_type: String,
    #[arg(short = 't', long, env)]
    pub api_token: String,
    #[arg(short = 'z', long, env)]
    pub zone_id: String,
    #[arg(short = 'e', long, env,value_enum,default_value_t = Environment::Production)]
    pub environment: Environment,
    #[arg(short = 'd', long, env)]
    pub directory_url: Option<String>,
    #[arg(short = 's', long, env)]
    pub staging_directory_url: Option<String>,
    #[arg(short = 'p', long, env)]
    pub cert_path: String,
}

impl CliInput {
    pub fn split_identifiers(&self) -> Vec<String> {
        self.identifiers
            .iter()
            .flat_map(|s| s.split(',').map(str::trim).map(String::from))
            .collect()
    }
    pub fn split_contact_mail(&self) -> Vec<String> {
        self.contact_mail
            .iter()
            .flat_map(|s| s.split(',').map(str::trim).map(String::from))
            .collect()
    }
    pub fn new() -> Self {
        let tmp = CliInput::parse();
        let processed_identifiers = tmp.split_identifiers();
        let processed_contact_mail = tmp.split_contact_mail();
        CliInput {
            identifiers: processed_identifiers,
            contact_mail: processed_contact_mail,
            ..tmp
        }
    }
    pub fn identifiers(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .map(String::as_str)
            .clone()
            .collect()
    }
}
