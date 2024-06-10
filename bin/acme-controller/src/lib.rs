use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
pub struct CliInput {
    #[arg(short = 'i', long, env)]
    pub identifiers: String,
    #[arg(short = 'm', long, env)]
    pub contact_mail: String,
    #[arg(short = 'c', long, env)]
    pub challange_type: String,
    #[arg(short = 't', long, env)]
    pub api_token: String,
    #[arg(short = 'z', long, env)]
    pub zone_id: String,
}
