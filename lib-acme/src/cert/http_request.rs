use reqwest::{header, Client, Response};
use url::Url;
use super::errors::AcmeErrors;

const JOSE_JSON: &str = "application/jose+json";

pub(crate) async fn post(
    client: &Client,
    url_value: Url,
    body: String,
) -> Result<Response, AcmeErrors> {
    Ok(client
        .post(url_value)
        .header(header::CONTENT_TYPE, JOSE_JSON)
        .body(body)
        .send()
        .await?)
}
