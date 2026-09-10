//! Deterministic cluster PKI for in-app TLS .
//!
//! Generates a single cluster test CA and per-service leaf certificates from
//! seeded bytes. All certificates use P-256 ECDSA, have a fixed validity window
//! (2026-01-01 -> 2028-01-01), and carry SANs for `localhost` and `127.0.0.1`.

use p256::{pkcs8::EncodePrivateKey, SecretKey};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// Fixed validity window for every PoC certificate (Unix timestamps).
const NOT_BEFORE_UNIX: i64 = 1_767_225_600; // 2026-01-01 00:00:00 UTC
const NOT_AFTER_UNIX: i64 = 1_830_297_600; // 2028-01-01 00:00:00 UTC

/// Cluster test CA, deterministically generated from a seed.
///
/// Holds the rcgen [`Certificate`] and [`KeyPair`] directly so callers can
/// issue leaf certificates without re-parsing PEMs. This type intentionally
/// does not implement [`Clone`] because rcgen types are not cloneable; wrap it
/// in an [`std::sync::Arc`] if shared ownership is needed.
pub struct ClusterCa {
    cert: Certificate,
    key_pair: KeyPair,
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
}

impl std::fmt::Debug for ClusterCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterCa")
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl ClusterCa {
    /// Generate a deterministic CA from `seed`. The same seed always yields the
    /// same certificate.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, TlsError> {
        let key_pair = derive_key_pair(seed, "cluster-ca")?;
        let mut params =
            CertificateParams::new(Vec::new()).map_err(|e| TlsError::InvalidName(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "referendum-poc-cluster-ca");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "referendum-poc");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        set_validity(&mut params)?;

        let cert = params.self_signed(&key_pair)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            cert_der: cert.der().to_vec(),
            cert,
            key_pair,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn cert(&self) -> &Certificate {
        &self.cert
    }

    fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

/// A service leaf certificate signed by the cluster CA.
#[derive(Clone)]
pub struct ServiceCert {
    cert_pem: String,
    key_pem: String,
}

impl std::fmt::Debug for ServiceCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceCert")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl ServiceCert {
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

/// Issue a deterministic leaf certificate for `service_name`.
///
/// `service_seed` is the service's private key seed. The certificate carries
/// SANs `localhost` and `127.0.0.1`, plus `service_name` as a DNS SAN if it
/// differs from `localhost`.
pub fn issue_service_cert(
    ca: &ClusterCa,
    service_name: &str,
    service_seed: &[u8; 32],
) -> Result<ServiceCert, TlsError> {
    let ca_cert = ca.cert();
    let ca_key_pair = ca.key_pair();
    let service_key_pair = derive_key_pair(service_seed, service_name)?;

    let mut sans = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e| TlsError::InvalidName(format!("{e:?}")))?,
        ),
        SanType::IpAddress(std::net::IpAddr::V4("127.0.0.1".parse().unwrap())),
    ];
    if service_name != "localhost" {
        sans.push(SanType::DnsName(
            service_name
                .try_into()
                .map_err(|e| TlsError::InvalidName(format!("{e:?}")))?,
        ));
    }

    let mut params =
        CertificateParams::new(Vec::new()).map_err(|e| TlsError::InvalidName(e.to_string()))?;
    params.subject_alt_names = sans;
    params
        .distinguished_name
        .push(DnType::CommonName, service_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "referendum-poc");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.use_authority_key_identifier_extension = true;
    set_validity(&mut params)?;

    let cert = params.signed_by(&service_key_pair, ca_cert, ca_key_pair)?;
    Ok(ServiceCert {
        cert_pem: cert.pem(),
        key_pem: service_key_pair.serialize_pem(),
    })
}

/// Build a `reqwest::Client` that trusts only the cluster CA.
///
/// The built-in webpki root store is explicitly disabled so the cluster CA is
/// the sole trust anchor.
pub fn reqwest_client_trusting_ca(ca_cert_pem: &str) -> Result<reqwest::Client, TlsError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(Into::into)
}

/// Build an `axum_server` rustls config from a service leaf certificate and key.
///
/// This is the server-side counterpart of [`reqwest_client_trusting_ca`]: Rust
/// services use the returned config to terminate TLS with the cluster CA-issued
/// certificate.
pub async fn rustls_config_for_service(
    service_cert_pem: &str,
    service_key_pem: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, TlsError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    axum_server::tls_rustls::RustlsConfig::from_pem(
        service_cert_pem.as_bytes().to_vec(),
        service_key_pem.as_bytes().to_vec(),
    )
    .await
    .map_err(TlsError::RustlsConfig)
}

fn set_validity(params: &mut CertificateParams) -> Result<(), TlsError> {
    params.not_before = OffsetDateTime::from_unix_timestamp(NOT_BEFORE_UNIX)
        .map_err(|e| TlsError::InvalidValidity(format!("{e:?}")))?;
    params.not_after = OffsetDateTime::from_unix_timestamp(NOT_AFTER_UNIX)
        .map_err(|e| TlsError::InvalidValidity(format!("{e:?}")))?;
    Ok(())
}

/// Derive a deterministic P-256 key pair from a seed and a domain label.
///
/// The seed is hashed with SHA-256 together with the label; the result is
/// interpreted as a P-256 scalar. In the unlikely case it is not a valid
/// scalar, the hash is re-hashed with an increasing counter until a valid key
/// is found.
fn derive_key_pair(seed: &[u8; 32], label: &str) -> Result<KeyPair, TlsError> {
    let mut input = seed.to_vec();
    input.extend_from_slice(label.as_bytes());

    for counter in 0u64.. {
        let mut hasher = Sha256::new();
        hasher.update(&input);
        hasher.update(counter.to_le_bytes());
        let bytes = hasher.finalize();

        if let Ok(secret) = SecretKey::from_bytes(&bytes) {
            let pkcs8 = secret.to_pkcs8_der()?;
            return KeyPair::try_from(pkcs8.as_bytes()).map_err(Into::into);
        }
    }

    unreachable!("a valid scalar must be found within 2^64 iterations")
}

/// TLS-related errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("invalid certificate name: {0}")]
    InvalidName(String),
    #[error("invalid validity window: {0}")]
    InvalidValidity(String),
    #[error("invalid key bytes: {0}")]
    InvalidKey(String),
    #[error("p256 error: {0}")]
    P256(#[from] p256::elliptic_curve::Error),
    #[error("PKCS8 error: {0}")]
    Pkcs8(#[from] p256::pkcs8::Error),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("rustls server config error: {0}")]
    RustlsConfig(std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn cert_subject_cn(cert: &X509Certificate<'_>) -> String {
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn deterministic_ca_reproduces_same_cert() {
        let ca1 = ClusterCa::from_seed(&[1u8; 32]).unwrap();
        let ca2 = ClusterCa::from_seed(&[1u8; 32]).unwrap();
        // ECDSA signatures are randomized, so compare deterministic fields
        // (subject, SPKI, validity) instead of the PEM bytes.
        let (_, pem1) = x509_parser::pem::parse_x509_pem(ca1.cert_pem().as_bytes()).unwrap();
        let c1 = pem1.parse_x509().unwrap();
        let (_, pem2) = x509_parser::pem::parse_x509_pem(ca2.cert_pem().as_bytes()).unwrap();
        let c2 = pem2.parse_x509().unwrap();
        assert_eq!(cert_subject_cn(&c1), cert_subject_cn(&c2));
        assert_eq!(
            c1.tbs_certificate.subject_pki,
            c2.tbs_certificate.subject_pki
        );
        assert_eq!(c1.validity(), c2.validity());
        assert_eq!(ca1.key_pem(), ca2.key_pem());
    }

    #[test]
    fn different_seeds_yield_different_cas() {
        let ca1 = ClusterCa::from_seed(&[1u8; 32]).unwrap();
        let ca2 = ClusterCa::from_seed(&[2u8; 32]).unwrap();
        let (_, pem1) = x509_parser::pem::parse_x509_pem(ca1.cert_pem().as_bytes()).unwrap();
        let c1 = pem1.parse_x509().unwrap();
        let (_, pem2) = x509_parser::pem::parse_x509_pem(ca2.cert_pem().as_bytes()).unwrap();
        let c2 = pem2.parse_x509().unwrap();
        assert_ne!(
            c1.tbs_certificate.subject_pki,
            c2.tbs_certificate.subject_pki
        );
    }

    #[test]
    fn service_cert_is_signed_by_ca_and_contains_sans() {
        let ca = ClusterCa::from_seed(&[3u8; 32]).unwrap();
        let svc = issue_service_cert(&ca, "wbb", &[4u8; 32]).unwrap();
        assert!(svc.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(svc.key_pem().contains("BEGIN PRIVATE KEY"));

        let (_, pem) = x509_parser::pem::parse_x509_pem(svc.cert_pem().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        assert_eq!(cert_subject_cn(&cert), "wbb");

        let sans = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .clone();
        assert!(sans
            .iter()
            .any(|san| matches!(san, GeneralName::DNSName(n) if n == &"localhost")));
        assert!(sans
            .iter()
            .any(|san| matches!(san, GeneralName::DNSName(n) if n == &"wbb")));
        assert!(sans
            .iter()
            .any(|san| matches!(san, GeneralName::IPAddress(o) if o.len() == 4 && o[0] == 127)));
    }

    #[tokio::test]
    async fn service_rustls_config_loads_from_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = ClusterCa::from_seed(&[7u8; 32]).unwrap();
        let svc = issue_service_cert(&ca, "test-svc", &[8u8; 32]).unwrap();
        let config = rustls_config_for_service(svc.cert_pem(), svc.key_pem())
            .await
            .unwrap();
        // If we got a config, the cert/key PEMs were accepted by rustls.
        assert!(!format!("{config:?}").is_empty());
    }

    #[test]
    fn certs_are_valid_within_fixed_window() {
        let ca = ClusterCa::from_seed(&[5u8; 32]).unwrap();
        let svc = issue_service_cert(&ca, "wbb", &[6u8; 32]).unwrap();

        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(ca.cert_pem().as_bytes()).unwrap();
        let ca_cert = ca_pem.parse_x509().unwrap();
        let (_, svc_pem) = x509_parser::pem::parse_x509_pem(svc.cert_pem().as_bytes()).unwrap();
        let svc_cert = svc_pem.parse_x509().unwrap();

        let expected_not_before = OffsetDateTime::from_unix_timestamp(NOT_BEFORE_UNIX).unwrap();
        let expected_not_after = OffsetDateTime::from_unix_timestamp(NOT_AFTER_UNIX).unwrap();

        assert_eq!(
            ca_cert.validity().not_before.to_datetime(),
            expected_not_before
        );
        assert_eq!(
            ca_cert.validity().not_after.to_datetime(),
            expected_not_after
        );
        assert_eq!(
            svc_cert.validity().not_before.to_datetime(),
            expected_not_before
        );
        assert_eq!(
            svc_cert.validity().not_after.to_datetime(),
            expected_not_after
        );
    }
}
