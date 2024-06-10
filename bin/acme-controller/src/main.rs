use std::fs::File;
use std::io::Write;
use acme_controller::CliInput;
use clap::Parser;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use lib_acme::cert::cert_menager::{
    choose_challanges, dns_01_challange, fetch_authorizations, generate_csr,
};
use lib_acme::cert::cert_menager::{
    fetch_order_status, get_challanges_tokens, new_account, new_directory, order_finalization,
    respond_to_challange,submit_order
};
use lib_acme::cert::dns_menagment::delete_dns_record;
use reqwest::Client;
use serde_json::Value;

#[tokio::main]
async fn main(){
    let args = CliInput::parse();

    let identifiers = vec![args.identifiers.as_str()];
    let contact_email = args.contact_email;
    let challange_type = args.challange_type.as_str();
    let api_token = args.api_token.as_str();
    let zone_id = args.zone_id.as_str();

    let ec_key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
    let client = Client::new();
    let urls = new_directory().await;

    let account = new_account(
        &client,
        urls.clone(),
        contact_email.clone(),
        ec_key_pair.clone(),
    )
    .await;

    let account_url = account
        .headers()
        .get("location")
        .ok_or("Location header missing")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let order = submit_order(
        &client,
        urls.clone(),
        identifiers.clone(),
        ec_key_pair.clone(),
        account_url.to_string(),
    )
    .await;

    let order_url = order
        .headers()
        .get("location")
        .ok_or("Location header missing")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned(); // Make an owned copy of the URL

    println!("Order URL: {}", order_url);
    // Deserialize the JSON body for further processing
    let order_body: Value = order.json().await.unwrap();

    // Now that we have both `order_url` and `order_body`, we no longer need the original `order`
    let authorizations = fetch_authorizations(order_body).await;
    let challanges = choose_challanges(authorizations, challange_type).await;

    let tokens = get_challanges_tokens(challanges.clone()).await;
    // processing dns-01 challenges
    if challange_type == "dns-01" {
        dns_01_challange(
            tokens,
            identifiers.clone(),
            ec_key_pair.clone(),
            api_token,
            zone_id,
        )
        .await;
    }
    // Respond to the challenges
    for challange in challanges.clone() {
        respond_to_challange(
            challange.clone(),
            ec_key_pair.clone(),
            account_url.to_string().clone(),
        )
        .await;
    }
    println!("Challenge responded to, waiting for the order to complete...");
    loop {
        let order_status = fetch_order_status(&client, &order_url).await.unwrap();
        let status = order_status["status"].as_str().unwrap_or("unknown");

        match status {
            "valid" => {
                println!("Order is completed successfully. Downloading certificate...");
                let certificate_url = order_status["certificate"].as_str().unwrap();
                println!("Certificate URL: {}", certificate_url);
                let certificate = client.get(certificate_url).send().await.unwrap();
                let certificate_body = certificate.text().await.unwrap();
                // Define the path to save the certificate
                let path = "certificate.pem"; // Adjust the path as necessary
                                              // Write to a file
                let mut file = File::create(path).unwrap();
                file.write_all(certificate_body.as_bytes()).unwrap();
                println!("Certificate saved to {}", path);
                for id in identifiers.clone() {
                    delete_dns_record(api_token, zone_id, id).await;
                }
                break;
            }
            "invalid" => {
                println!("Order has failed.");
                break;
            }
            "pending" => {
                println!("Order is pending...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            "ready" => {
                println!("Order is ready... finalizing.");
                let finalization_url = order_status["finalize"].as_str().unwrap();
                let csr = generate_csr(identifiers.clone()).unwrap();
                let _response = order_finalization(
                    csr,
                    urls.clone(),
                    ec_key_pair.clone(),
                    account_url.to_string(),
                    finalization_url.to_string(),
                )
                .await;
            }
            "processing" => {
                println!("Order is processing...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            _ => {
                println!("Order status: {}", status);
                break;
            }
        }
    }
}