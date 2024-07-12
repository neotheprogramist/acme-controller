use base64::DecodeError;
use josekit::JoseError;
use reqwest::header::ToStrError;
use reqwest::Error as ReqwestError;
use serde_json::Error as SerdeError;
use std::fmt::Error as FmtError;
use thiserror::Error;

/// Represents all possible errors that can occur during operations involving the ACME protocol.
/// This enum encompasses a variety of errors such as network failures, data conversion issues,
/// cryptographic errors, and JSON processing issues, among others.
///
/// # Variants
///
/// - `RequestFailed`: Errors that occur during HTTP requests. Wrapped errors from the `reqwest` library.
/// - `ToStrError`: Occurs when there is a failure in converting a type to a `String`. This typically involves converting non-string data that should be in string format but isn't, due to encoding or format errors.
/// - `MissingNonce`: Indicates that a replay nonce, which is expected in the server response, is not present. This is critical for maintaining the state and security of communications.
/// - `HeaderToStrError`: Arises when converting HTTP header values to strings fails. This can happen if the header content is not properly encoded.
/// - `JoseError`: Related to failures in processing JSON Object Signing and Encryption (JOSE) tasks. This covers a range of issues from signing, encryption, or parsing of JOSE payloads.
/// - `MissingLocationHeader`: Emitted when an HTTP response does not contain a 'location' header where one is expected, typically in responses that should direct the client to a new resource location.
/// - `MissingKid`: Triggered when a Key Identifier ('kid') is required but absent in a JSON Web Signature (JWS). This is essential for identifying keys in scenarios where multiple keys are in use.
/// - `DecodeError`: Occurs during the decoding of data, which could be due to incorrect format, corruption, or unsupported encoding.
/// - `SerdeError`: Happens during serialization or deserialization processes using Serde, indicating that data could not be properly converted to or from a serialized format.
/// - `ErrorStack`: Represents errors related to OpenSSL operations, often cryptographic in nature, which could involve key generation, encryption, decryption, or certificate processing.
/// - `MissingKey`: Indicates that a necessary cryptographic key or a key component required for an operation is missing. This could involve public, private, or symmetric keys depending on the context.
/// - `ConversionError`: A general error category for issues related to type conversion that are not covered by more specific error types.
/// - `ChallangeNotFound`: Indicates that a specific challenge required for validating an entity's control over a domain was not found in the ACME server's response. This is critical for the domain validation process.

#[derive(Debug, Error)]
pub enum AcmeErrors {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] ReqwestError),

    #[error("Failed to convert to String: {0}")]
    ToStrError(#[from] FmtError),

    #[error("Replay nonce expected but not found in the response")]
    MissingNonce,

    #[error("Failed to convert HTTP header value to string: {0}")]
    HeaderToStrError(#[from] ToStrError),

    #[error("JOSE processing error: {0}")]
    JoseError(#[from] JoseError),

    #[error("Expected 'location' header is missing in the HTTP response")]
    MissingLocationHeader,

    #[error("Key Identifier ('kid') is missing when required")]
    MissingKid,

    #[error("Data decoding error: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("Serialization or deserialization error using Serde: {0}")]
    SerdeError(#[from] SerdeError),

    #[error("OpenSSL related error: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),

    #[error("A required cryptographic key or key component is missing")]
    MissingKey,

    #[error("General error related to type conversion")]
    ConversionError,

    #[error("The specified challenge was not found in the server's response")]
    ChallangeNotFound,
    #[error("Error in making order")]
    OrderError,
    #[error("Error in making account")]
    AccountError,
    #[error("Error in parsing url")]
    ParseError(#[from] url::ParseError),
    #[error("Error in opening/reading file")]
    IOError(#[from] std::io::Error),
    #[error("Error in certificate procedure")]
    CertificateProcudureFailed,
}
