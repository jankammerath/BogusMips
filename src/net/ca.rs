//! A local certificate authority for TLS interception: one CA certificate
//! (installed on the emulator as a system trust anchor) plus per-host leaf
//! certificates generated and cached on demand.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

/// A generated CA and a cache of leaf certificates signed by it.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "BogusMips Proxy CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "BogusMips");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // The CA is generated fresh per capture session, so a short validity is
    // fine — and required: Chromium/Cronet applies its ~398-day leaf-validity
    // limit to the trust anchor too, rejecting a long-lived CA with
    // ERR_CERT_VALIDITY_TOO_LONG. A one-day backdate absorbs emulator skew.
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(300);
    params
}

impl CertAuthority {
    pub fn new() -> Result<Self, String> {
        let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let params = ca_params();
        let ca_cert = params.self_signed(&ca_key).map_err(|e| e.to_string())?;
        let ca_cert_der = ca_cert.der().clone();
        let ca_cert_pem = ca_cert.pem();
        let issuer = Issuer::new(params, ca_key);
        Ok(Self {
            issuer,
            ca_cert_der,
            ca_cert_pem,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// The OpenSSL "old" subject hash, which Android uses as the file name
    /// (`<hash>.0`) of a system trust anchor.
    pub fn android_cert_filename(&self) -> String {
        format!("{:08x}.0", subject_hash_old(&self.ca_cert_der))
    }

    /// A leaf certificate (and signing key) for `host`, generated on first use.
    pub fn cert_for(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        if let Some(existing) = self.leaves.lock().unwrap().get(host) {
            return Ok(existing.clone());
        }
        let certified = Arc::new(self.generate_leaf(host)?);
        self.leaves
            .lock()
            .unwrap()
            .insert(host.to_owned(), certified.clone());
        Ok(certified)
    }

    fn generate_leaf(&self, host: &str) -> Result<CertifiedKey, String> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![san_for(host)];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Chromium (WebView / Cronet) rejects leaf certificates whose validity
        // period exceeds 398 days (ERR_CERT_VALIDITY_TOO_LONG), so keep the
        // window well under that. A one-day backdate absorbs emulator clock skew.
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(300);

        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf: Certificate = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| e.to_string())?;

        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| format!("leaf key: {e}"))?;
        let signing_key = any_supported_type(&key_der).map_err(|e| e.to_string())?;
        // Send only the leaf: the client already trusts our CA as a root, and
        // including the long-lived CA in the chain makes Chromium/Cronet reject
        // the whole chain with ERR_CERT_VALIDITY_TOO_LONG.
        let chain = vec![leaf.der().clone()];
        Ok(CertifiedKey::new(chain, signing_key))
    }
}

fn san_for(host: &str) -> SanType {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => match ServerName::try_from(host.to_owned()) {
            Ok(ServerName::DnsName(dns)) => SanType::DnsName(dns.as_ref().to_owned().try_into().unwrap()),
            _ => SanType::DnsName(host.to_owned().try_into().unwrap_or_else(|_| "invalid.invalid".try_into().unwrap())),
        },
    }
}

/// Resolves the leaf certificate by the TLS ClientHello's SNI.
#[derive(Debug)]
pub struct SniResolver(pub Arc<CertAuthority>);

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name().unwrap_or("localhost");
        self.0.cert_for(host).ok()
    }
}

impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority").finish_non_exhaustive()
    }
}

/// `(tag, content range, next offset)` for the DER TLV at `pos`.
fn read_tlv(data: &[u8], pos: usize) -> Option<(u8, std::ops::Range<usize>, usize)> {
    let tag = *data.get(pos)?;
    let first_len = *data.get(pos + 1)?;
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *data.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, start..end, end))
}

/// The DER bytes of a certificate's subject Name, including its SEQUENCE
/// header (what OpenSSL hashes for the trust-anchor file name).
fn subject_der(cert: &[u8]) -> Option<&[u8]> {
    let (_, cert_body, _) = read_tlv(cert, 0)?; // Certificate SEQUENCE
    let (_, tbs, _) = read_tlv(cert, cert_body.start)?; // tbsCertificate SEQUENCE
    let mut pos = tbs.start;
    // tbs children: [0] version?, serial, sigAlg, issuer, validity, subject, ...
    let (first_tag, _, after_first) = read_tlv(cert, pos)?;
    pos = if first_tag == 0xa0 { after_first } else { pos };
    // Skip serial, sigAlg, issuer, validity to reach subject (the 5th here).
    for _ in 0..4 {
        let (_, _, next) = read_tlv(cert, pos)?;
        pos = next;
    }
    let start = pos;
    let (_, _, end) = read_tlv(cert, pos)?;
    cert.get(start..end)
}

fn subject_hash_old(cert: &[u8]) -> u32 {
    let subject = subject_der(cert).unwrap_or(&[]);
    let digest = Md5::digest(subject);
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    /// Drives a rustls handshake between buffered connections, without sockets.
    fn handshake(mut client: ClientConnection, mut server: ServerConnection) -> ClientConnection {
        for _ in 0..20 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut buf.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        client
    }

    #[test]
    fn leaf_certs_chain_to_the_ca_and_match_the_host() {
        let ca = Arc::new(CertAuthority::new().unwrap());
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SniResolver(ca.clone()))),
        );

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let name = ServerName::try_from("api.example.com").unwrap();
        let client = ClientConnection::new(client_config, name).unwrap();
        let server = ServerConnection::new(server_config).unwrap();
        let client = handshake(client, server);

        // The handshake completed, proving the leaf validates against our CA
        // (sent as the trust anchor, not in the presented chain).
        assert!(!client.is_handshaking());
        let chain = client.peer_certificates().expect("server cert");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn caches_leaf_certificates() {
        let ca = CertAuthority::new().unwrap();
        let a = ca.cert_for("example.com").unwrap();
        let b = ca.cert_for("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &ca.cert_for("other.com").unwrap()));
        // IP hosts are valid too.
        assert!(ca.cert_for("10.0.2.2").is_ok());
    }

    #[test]
    fn android_filename_is_stable_hex() {
        let ca = CertAuthority::new().unwrap();
        let name = ca.android_cert_filename();
        assert!(name.ends_with(".0") && name.len() == 10);
        assert!(name[..8].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ca.ca_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn subject_hash_matches_openssl() {
        // A fixed CA certificate whose `openssl x509 -subject_hash_old`
        // output (b13f7cfc) is pinned here as an independent oracle.
        let der = include_bytes!("../../media/test/subject_hash_ca.der");
        assert_eq!(subject_hash_old(der), 0xb13f_7cfc);
        assert_eq!(format!("{:08x}", subject_hash_old(der)), "b13f7cfc");
    }
}
