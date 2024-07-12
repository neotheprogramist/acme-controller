use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
pub struct CliInput {
    #[arg(short = 'i', long, env)]
    pub domain_identifiers: Vec<String>,
    #[arg(short = 'm', long, env)]
    pub contact_mails: Vec<String>,
    #[arg(short = 't', long, env)]
    pub api_token: String,
    #[arg(short = 'z', long, env)]
    pub zone_id: String,
    #[arg(short = 'u', long, env)]
    pub url: Url,
    #[arg(short = 'p', long, env)]
    pub cert_path: PathBuf,
    #[arg(short = 'r', long, env)]
    pub renewal_threshold: i32,
}

impl CliInput {
    pub fn split_identifiers(&self) -> Vec<String> {
        self.domain_identifiers
            .iter()
            .flat_map(|s| s.split(',').map(str::trim).map(String::from))
            .collect()
    }
    pub fn split_contact_mail(&self) -> Vec<String> {
        self.contact_mails
            .iter()
            .flat_map(|s| s.split(',').map(str::trim).map(String::from))
            .collect()
    }
    pub fn new() -> Self {
        let tmp = CliInput::parse();
        let processed_identifiers = tmp.split_identifiers();
        let processed_contact_mail = tmp.split_contact_mail();
        CliInput {
            domain_identifiers: processed_identifiers,
            contact_mails: processed_contact_mail,
            ..tmp
        }
    }
    pub fn domain_identifiers(&self) -> Vec<&str> {
        self.domain_identifiers
            .iter()
            .map(String::as_str)
            .clone()
            .collect()
    }
}
