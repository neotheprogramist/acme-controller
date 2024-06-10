use reqwest::{header, Client};

const JOSE_JSON: &str = "application/jose+json";
pub async fn post(client: &Client, url_value: String, body: String) -> reqwest::Response {
    client
        .post(url_value)
        .header(header::CONTENT_TYPE, JOSE_JSON)
        .body(body)
        .send()
        .await
        .unwrap()
}
