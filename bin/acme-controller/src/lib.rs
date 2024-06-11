use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
pub struct CliInput {
    #[arg(short = 'i', long, env)]
    pub identifiers: Vec<String>,
    #[arg(short = 'm', long, env)]
    pub contact_mail: String,
    #[arg(short = 'c', long, env)]
    pub challange_type: String,
    #[arg(short = 't', long, env)]
    pub api_token: String,
    #[arg(short = 'z', long, env)]
    pub zone_id: String,
}

impl CliInput {
    pub fn split_identifiers(&self) -> Vec<String> {
        self.identifiers
            .iter()
            .flat_map(|s| s.split(',').map(str::trim).map(String::from))
            .collect()
    }
    pub fn new() -> Self {
        let tmp = CliInput::parse();
        let processed_identifiers = tmp.split_identifiers();
        return CliInput {
            identifiers: processed_identifiers,
            ..tmp
        };
    }
    pub fn identifiers(&self) -> Vec<&str> {
        self.identifiers.iter().map(|x| x.as_str()).to_owned().collect()
    }

}
