use std::fmt::Display;

use crate::cert::types::base64;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use josekit::{
    jwk::alg::ec::EcKeyPair,
    jws::{JwsHeader, ES256},
    jwt::JwtPayload,
};
use serde::Serialize;
use url::Url;

use super::errors::AcmeErrors;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256
    Es256,}
impl Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningAlgorithm::Es256 => write!(f, "ES256"),
        }
    }
}

#[derive(Serialize)]
struct JwtComponents {
    protected: String,
    payload: String,
    signature: String,
}

impl JwtComponents {
    fn new(protected: String, payload: String, signature: Vec<u8>) -> Self {
        Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature),
        }
    }
}
pub(crate) fn create_jws(
    nonce: &str,
    payload: &JwtPayload,
    url: Url,
    ec_key_pair: &EcKeyPair,
    kid: Option<Url>,
) -> Result<String, AcmeErrors> {
    // You would typically load your ECDSA P-256 key from secure storage or configuration
    // Convert key to JWK format for including in the protected header
    let mut header = JwsHeader::new();
    if kid.is_some() {
        let value = kid.ok_or(AcmeErrors::MissingKid)?;
        header.set_key_id(value); // Set the Key ID
    } else {
        let jwk = ec_key_pair.to_jwk_public_key();
        header.set_jwk(jwk); // Set the JWK
    }

    header.set_algorithm(SigningAlgorithm::Es256.to_string());

    //decoding nonce
    let nonce = URL_SAFE_NO_PAD.decode(nonce.as_bytes())?;
    header.set_nonce(nonce.clone());
    header.set_url(url);

    let encoded_header = base64(header.as_ref())?;
    let encoded_payload = base64(&payload.as_ref())?;
    let signer = ES256.signer_from_pem(ec_key_pair.to_pem_private_key())?;
    //Create and sign the JWT
    let signature = signer.sign(format!("{encoded_header}.{encoded_payload}").as_bytes())?;
    let jwt_components = JwtComponents::new(encoded_header, encoded_payload, signature);
    Ok(serde_json::to_string(&jwt_components)?)
}
