use reqwest::Client;
use reqwest::Response;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

impl DnsRecord {
    pub fn new(domain: &str, content: &str) -> Self {
        Self {
            record_type: "TXT".to_string(),
            name: format!("_acme-challenge.{domain}"),
            content: content.to_string(),
            ttl: 60,
        }
    }
}

use super::errors::AcmeErrors;
pub(crate) async fn post_dns_record(
    body: String,
    domain: &str,
    api_token: &str,
    zone_id: &str,
) -> Result<Response, AcmeErrors> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
    let client = reqwest::Client::new();
    let record = DnsRecord::new(domain, &body);
    let record_json = serde_json::to_string(&record)?;
    Ok(client
        .post(&url)
        .bearer_auth(api_token)
        .body(record_json)
        .send()
        .await?)
}
pub(crate) async fn get_acme_challenge_record_ids(
    api_token: &str,
    zone_id: &str,
    domain: &str,
) -> Result<Vec<String>, AcmeErrors> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name=_acme-challenge.{domain}"
    );

    let client = Client::new();

    let response = client.get(&url).bearer_auth(api_token).send().await?;

    let body = response.text().await?;
    let json: Value = serde_json::from_str(&body)?;

    let mut ids = Vec::new();

    // Check each record to see if it's a TXT record with the desired prefix
    if let Some(records) = json["result"].as_array() {
        for record in records {
            if record["type"] == "TXT"
                && record["name"]
                    .as_str()
                    .map_or(false, |n| n.starts_with("_acme-challenge"))
            {
                if let Some(id) = record["id"].as_str() {
                    ids.push(id.to_string());
                }
            }
        }
    }
    Ok(ids)
}
pub(crate) async fn delete_dns_record(
    api_token: &str,
    zone_id: &str,
    domain: &str,
) -> Result<(), AcmeErrors> {
    let ids = get_acme_challenge_record_ids(api_token, zone_id, domain).await?;
    let client = reqwest::Client::new();
    for id in ids {
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}");
        let _ = client.delete(&url).bearer_auth(api_token).send().await;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::env;

    use crate::cert::errors::AcmeErrors;
    #[tokio::test]
    async fn test_post_dns_record() -> Result<(), AcmeErrors> {
        let api_token = env::var("API_TOKEN").expect("API_TOKEN must be set");
        let zone_id = env::var("ZONE_ID").expect("ZONE_ID must be set");
        let domain = "mateuszchudy.lat";
        let body = "test".to_string();
        let response = super::post_dns_record(body, domain, &api_token, &zone_id).await?;
        println!("{:?}", response.text().await?);
        Ok(())
        //assert_eq!(response.status().as_u16(), 200);
    }
    #[tokio::test]
    async fn test_get_dns_record_id() -> Result<(), AcmeErrors> {
        let api_token = env::var("API_TOKEN").expect("API_TOKEN must be set");
        let zone_id = env::var("ZONE_ID").expect("ZONE_ID must be set");
        let domain = "mateuszchudy.lat";
        println!(
            "{:?}",
            super::get_acme_challenge_record_ids(&api_token, &zone_id, domain).await?
        );
        Ok(())
    }
    #[tokio::test]
    async fn test_delete_dns_record() -> Result<(), AcmeErrors> {
        let api_token = env::var("API_TOKEN").expect("API_TOKEN must be set");
        let zone_id = env::var("ZONE_ID").expect("ZONE_ID must be set");
        let domain = "mateuszchudy.lat";
        super::delete_dns_record(&api_token, &zone_id, domain).await?;
        Ok(())
    }
}
