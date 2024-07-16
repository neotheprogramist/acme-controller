use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::alg::ec::EcKeyPair;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Req;
use serde_json::json;
use std::collections::BTreeMap;

use super::errors::AcmeErrors;

pub(crate) fn get_key_authorization(
    token: &str,
    ec_key_pair: &EcKeyPair,
) -> Result<String, AcmeErrors> {
    let thumbprint = get_thumbprint(ec_key_pair)?;
    // Construct key authorization using the token and the thumbprint
    let key_authorization = format!("{token}.{thumbprint}");
    // Compute SHA-256 hash of the key authorization
    let key_auth_digest = hash(MessageDigest::sha256(), key_authorization.as_bytes())?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(key_auth_digest))
}
pub(crate) fn generate_csr(domain: Vec<&str>) -> Result<(String,Vec<u8>), AcmeErrors> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    // Build the X509 request with the domain name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, domain[0])?;
    let name = name_builder.build();

    let mut san_builder = SubjectAlternativeName::new();
    for d in domain {
        san_builder.dns(d);
    }

    let mut req_builder = X509Req::builder()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;
    // Add the SAN extension (Subject Alternative Name)
    let context = req_builder.x509v3_context(None);
    let san_extension = san_builder.build(&context)?;
    let mut stack = Stack::new()?;
    stack.push(san_extension)?;
    req_builder.add_extensions(&stack)?;
    req_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;

    let req = req_builder.build();
    let csr_der = req.to_der()?;
    let csr_base64 = BASE64_URL_SAFE_NO_PAD.encode(csr_der);
    Ok((csr_base64,pkey.private_key_to_pem_pkcs8()?))
}

pub(crate) fn get_thumbprint(ec_key_pair: &EcKeyPair) -> Result<String, AcmeErrors> {
    let jwk_json = ec_key_pair.to_jwk_public_key();
    let mut jwk_btree_map = BTreeMap::new();
    jwk_btree_map.insert(
        "crv",
        jwk_json.curve().ok_or(AcmeErrors::MissingKey)?.to_string(),
    );
    jwk_btree_map.insert("kty", jwk_json.key_type().to_string());
    jwk_btree_map.insert(
        "x",
        jwk_json
            .parameter("x")
            .ok_or(AcmeErrors::MissingKey)?
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_string(),
    );
    jwk_btree_map.insert(
        "y",
        jwk_json
            .parameter("y")
            .ok_or(AcmeErrors::MissingKey)?
            .as_str()
            .ok_or(AcmeErrors::ConversionError)?
            .to_string(),
    );
    // Convert to canonical JSON string
    let sorted_jwk_json = json!(jwk_btree_map).to_string();
    let jwk_digest = hash(MessageDigest::sha256(), sorted_jwk_json.as_bytes())?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(jwk_digest))
}
