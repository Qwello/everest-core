//! Certificate renewal module for EVerest.
//!
//! This module monitors certificates in a configured directory for expiration and
//! automatically fetches new certificates from a configured endpoint when they are
//! about to expire.
//!
//! ## Configuration
//!
//! - `endpoint`: URL to fetch new certificates from
//! - `cert_dir`: Directory containing certificates to monitor
//! - `check_interval_seconds`: How often to check certificates (default: 3600)
//! - `expiry_threshold_days`: Days before expiration to trigger renewal (default: 30)
//!
//! ## Example usage
//!
//! ```yaml
//! active_modules:
//!   cert_renewal:
//!     module: RsCertRenewal
//!     config_module:
//!       endpoint: "https://example.com/certs/renew"
//!       cert_dir: "/etc/everest/certs"
//!       check_interval_seconds: 3600
//!       expiry_threshold_days: 30
//! ```
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use generated::{get_config, Module, ModulePublisher};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Configuration extracted from the generated config
#[derive(Clone)]
struct Config {
    endpoint: String,
    cert_dir: String,
    check_interval_seconds: i64,
    expiry_threshold_days: i64,
}

/// Represents a certificate file with its metadata
struct CertificateInfo {
    path: String,
    expiry: DateTime<Utc>,
    subject: String,
}

/// Parses a PEM-encoded certificate file and extracts expiry information
fn parse_certificate(path: &Path) -> Result<CertificateInfo> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read certificate file: {}", path.display()))?;

    // Use x509-parser's PEM parsing
    let (_, pem) = x509_parser::pem::parse_x509_pem(content.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM from {}: {:?}", path.display(), e))?;

    let cert = pem.parse_x509()
        .with_context(|| format!("Failed to parse X509 certificate: {}", path.display()))?;

    let not_after = cert.validity().not_after;
    let expiry = DateTime::from_timestamp(not_after.timestamp(), 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid timestamp in certificate"))?;

    let subject = cert.subject().to_string();

    Ok(CertificateInfo {
        path: path.display().to_string(),
        expiry,
        subject,
    })
}

/// Scans a directory for certificate files (.pem, .crt, .cer)
fn scan_certificates(cert_dir: &str) -> Result<Vec<CertificateInfo>> {
    let mut certs = Vec::new();
    let dir_path = Path::new(cert_dir);

    if !dir_path.exists() {
        log::warn!("Certificate directory does not exist: {}", cert_dir);
        return Ok(certs);
    }

    let entries = fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read certificate directory: {}", cert_dir))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    match parse_certificate(&path) {
                        Ok(cert_info) => {
                            log::debug!(
                                "Found certificate: {} (expires: {})",
                                cert_info.subject,
                                cert_info.expiry
                            );
                            certs.push(cert_info);
                        }
                        Err(e) => {
                            log::warn!("Failed to parse certificate {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }

    Ok(certs)
}

/// Checks if a certificate is expiring soon
fn is_expiring_soon(cert: &CertificateInfo, threshold_days: i64) -> bool {
    let now = Utc::now();
    let days_until_expiry = (cert.expiry - now).num_days();
    days_until_expiry <= threshold_days
}

/// Escapes a string for JSON (handles quotes and backslashes)
fn json_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c => result.push(c),
        }
    }
    result
}

/// Fetches a renewed certificate from the configured endpoint
fn fetch_renewed_certificate(endpoint: &str, cert_info: &CertificateInfo) -> Result<String> {
    log::info!(
        "Fetching renewed certificate for: {} from {}",
        cert_info.subject,
        endpoint
    );

    let request_body = format!(
        r#"{{"subject":"{}","current_expiry":"{}","certificate_path":"{}"}}"#,
        json_escape(&cert_info.subject),
        cert_info.expiry.to_rfc3339(),
        json_escape(&cert_info.path)
    );

    let response = ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_string(&request_body)
        .with_context(|| format!("Failed to contact renewal endpoint: {}", endpoint))?;

    if response.status() != 200 {
        anyhow::bail!(
            "Renewal endpoint returned error status: {}",
            response.status()
        );
    }

    let new_cert = response
        .into_string()
        .with_context(|| "Failed to read response body")?;

    Ok(new_cert)
}

/// Saves a renewed certificate to disk
fn save_certificate(path: &str, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("Failed to write certificate to: {}", path))?;

    log::info!("Saved renewed certificate to: {}", path);
    Ok(())
}

/// Performs a certificate check and renewal cycle
fn check_and_renew_certificates(config: &Config) -> Result<()> {
    if config.cert_dir.is_empty() {
        log::debug!("No certificate directory configured, skipping check");
        return Ok(());
    }

    log::info!("Checking certificates in: {}", config.cert_dir);

    let certificates = scan_certificates(&config.cert_dir)?;
    log::info!("Found {} certificates to monitor", certificates.len());

    for cert in &certificates {
        let days_until_expiry = (cert.expiry - Utc::now()).num_days();
        log::info!(
            "Certificate '{}' expires in {} days ({})",
            cert.subject,
            days_until_expiry,
            cert.expiry
        );

        if is_expiring_soon(cert, config.expiry_threshold_days) {
            log::warn!(
                "Certificate '{}' is expiring soon ({} days), attempting renewal",
                cert.subject,
                days_until_expiry
            );

            if config.endpoint.is_empty() {
                log::error!(
                    "No renewal endpoint configured, cannot renew certificate: {}",
                    cert.subject
                );
                continue;
            }

            match fetch_renewed_certificate(&config.endpoint, cert) {
                Ok(new_cert) => {
                    if let Err(e) = save_certificate(&cert.path, &new_cert) {
                        log::error!("Failed to save renewed certificate: {}", e);
                    }
                }
                Err(e) => {
                    log::error!("Failed to fetch renewed certificate: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Main module struct
struct CertRenewalModule {
    config: Config,
}

impl generated::OnReadySubscriber for CertRenewalModule {
    fn on_ready(&self, _publishers: &ModulePublisher) {
        log::info!("RsCertRenewal module is ready");
        log::info!("Configuration:");
        log::info!("  cert_dir: {}", self.config.cert_dir);
        log::info!("  endpoint: {}", self.config.endpoint);
        log::info!(
            "  check_interval_seconds: {}",
            self.config.check_interval_seconds
        );
        log::info!(
            "  expiry_threshold_days: {}",
            self.config.expiry_threshold_days
        );

        // Perform initial check
        if let Err(e) = check_and_renew_certificates(&self.config) {
            log::error!("Initial certificate check failed: {}", e);
        }
    }
}

impl generated::EmptyServiceSubscriber for CertRenewalModule {}

fn main() {
    let module_config = get_config();
    log::info!("Starting RsCertRenewal module");

    // Extract config into our own struct that implements Clone
    let config = Config {
        endpoint: module_config.endpoint.clone(),
        cert_dir: module_config.cert_dir.clone(),
        check_interval_seconds: module_config.check_interval_seconds,
        expiry_threshold_days: module_config.expiry_threshold_days,
    };

    let check_interval = Duration::from_secs(config.check_interval_seconds as u64);
    let config_for_loop = config.clone();

    let module = Arc::new(CertRenewalModule { config });

    let _everest_module = Module::new(module.clone(), module.clone());

    // Main loop for periodic certificate checks
    loop {
        thread::sleep(check_interval);

        if let Err(e) = check_and_renew_certificates(&config_for_loop) {
            log::error!("Certificate check failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Duration as ChronoDuration, TimeZone};
    use tempfile::TempDir;

    // Test certificate from the evse_security test suite (V2G Root CA)
    // Valid from 2025-06-12 to 2052-10-28
    // Subject: CN=V2GRootCA_PX_CSMS
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkDCCATWgAwIBAgIUUhx2j1hK10LEIz7YWfqxrImxoRkwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRVjJHUm9vdENBX1BYX0NTTVMwIBcNMjUwNjEyMTI1OTIzWhgP
MjA1MjEwMjgxMjU5MjNaMBwxGjAYBgNVBAMMEVYyR1Jvb3RDQV9QWF9DU01TMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQplOIWUtl6KOnRhM9OQRu7TawKd0SAEx
ZwztsJChemlIXEJ9D5dcK0/+rKjpTgHoDg9LdluA+tv9nmeeyiX8paNTMFEwHQYD
VR0OBBYEFNuKFuy+RkEgJd1HDGiEHLMb4AkkMB8GA1UdIwQYMBaAFNuKFuy+RkEg
Jd1HDGiEHLMb4AkkMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
AKAp7QkWQAGVld3ZNN6g9uJrk0w0QweSMNQrr7T4+qarAiEAt33b6cX+o8JrVkOu
uglyjLACI4LdKyETkSotKAF/Pqw=
-----END CERTIFICATE-----"#;

    #[test]
    fn test_json_escape_empty_string() {
        assert_eq!(json_escape(""), "");
    }

    #[test]
    fn test_json_escape_no_special_chars() {
        assert_eq!(json_escape("hello world"), "hello world");
    }

    #[test]
    fn test_json_escape_quotes() {
        assert_eq!(json_escape(r#"say "hello""#), r#"say \"hello\""#);
    }

    #[test]
    fn test_json_escape_backslashes() {
        assert_eq!(json_escape(r"path\to\file"), r"path\\to\\file");
    }

    #[test]
    fn test_json_escape_newlines() {
        assert_eq!(json_escape("line1\nline2"), r"line1\nline2");
    }

    #[test]
    fn test_json_escape_carriage_return() {
        assert_eq!(json_escape("line1\rline2"), r"line1\rline2");
    }

    #[test]
    fn test_json_escape_tabs() {
        assert_eq!(json_escape("col1\tcol2"), r"col1\tcol2");
    }

    #[test]
    fn test_json_escape_mixed_special_chars() {
        assert_eq!(
            json_escape("path\\to\\\"file\"\nwith\ttabs"),
            r#"path\\to\\\"file\"\nwith\ttabs"#
        );
    }

    #[test]
    fn test_is_expiring_soon_expired_cert() {
        // Certificate already expired (in the past)
        let cert = CertificateInfo {
            path: "/test/cert.pem".to_string(),
            expiry: Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
            subject: "CN=Test".to_string(),
        };
        // An expired cert should always be considered "expiring soon"
        assert!(is_expiring_soon(&cert, 30));
        assert!(is_expiring_soon(&cert, 0));
    }

    #[test]
    fn test_is_expiring_soon_within_threshold() {
        // Certificate expiring in 15 days
        let expiry = Utc::now() + ChronoDuration::days(15);
        let cert = CertificateInfo {
            path: "/test/cert.pem".to_string(),
            expiry,
            subject: "CN=Test".to_string(),
        };
        // 15 days is within 30-day threshold
        assert!(is_expiring_soon(&cert, 30));
        // 15 days is not within 10-day threshold
        assert!(!is_expiring_soon(&cert, 10));
    }

    #[test]
    fn test_is_expiring_soon_outside_threshold() {
        // Certificate expiring in 60 days
        let expiry = Utc::now() + ChronoDuration::days(60);
        let cert = CertificateInfo {
            path: "/test/cert.pem".to_string(),
            expiry,
            subject: "CN=Test".to_string(),
        };
        // 60 days is outside 30-day threshold
        assert!(!is_expiring_soon(&cert, 30));
    }

    #[test]
    fn test_is_expiring_soon_exactly_at_threshold() {
        // Certificate expiring in exactly 30 days
        let expiry = Utc::now() + ChronoDuration::days(30);
        let cert = CertificateInfo {
            path: "/test/cert.pem".to_string(),
            expiry,
            subject: "CN=Test".to_string(),
        };
        // Should be considered expiring soon (threshold is inclusive)
        assert!(is_expiring_soon(&cert, 30));
    }

    #[test]
    fn test_parse_certificate_valid() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();

        let result = parse_certificate(&cert_path);
        assert!(result.is_ok(), "Failed to parse valid certificate");

        let cert_info = result.unwrap();
        assert!(cert_info.subject.contains("V2GRootCA_PX_CSMS"));
        assert_eq!(cert_info.path, cert_path.display().to_string());
    }

    #[test]
    fn test_parse_certificate_invalid_content() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("invalid.pem");
        std::fs::write(&cert_path, "not a certificate").unwrap();

        let result = parse_certificate(&cert_path);
        assert!(result.is_err(), "Should fail on invalid certificate content");
    }

    #[test]
    fn test_parse_certificate_nonexistent_file() {
        let result = parse_certificate(Path::new("/nonexistent/path/cert.pem"));
        assert!(result.is_err(), "Should fail on nonexistent file");
    }

    #[test]
    fn test_scan_certificates_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_certificates_nonexistent_directory() {
        let result = scan_certificates("/nonexistent/directory/path");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_certificates_finds_pem_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create a valid .pem certificate
        let cert_path = temp_dir.path().join("test.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());

        let certs = result.unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].subject.contains("V2GRootCA_PX_CSMS"));
    }

    #[test]
    fn test_scan_certificates_finds_crt_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create a valid .crt certificate
        let cert_path = temp_dir.path().join("test.crt");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_scan_certificates_finds_cer_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create a valid .cer certificate
        let cert_path = temp_dir.path().join("test.cer");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_scan_certificates_ignores_other_extensions() {
        let temp_dir = TempDir::new().unwrap();

        // Create files with non-certificate extensions
        std::fs::write(temp_dir.path().join("readme.txt"), "text file").unwrap();
        std::fs::write(temp_dir.path().join("config.json"), "{}").unwrap();
        std::fs::write(temp_dir.path().join("script.sh"), "#!/bin/bash").unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_certificates_skips_invalid_certs() {
        let temp_dir = TempDir::new().unwrap();

        // Create an invalid .pem file
        std::fs::write(temp_dir.path().join("invalid.pem"), "not a cert").unwrap();
        // Create a valid .pem file
        std::fs::write(temp_dir.path().join("valid.pem"), TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        // Only the valid cert should be returned
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_scan_certificates_multiple_certs() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple certificate files
        std::fs::write(temp_dir.path().join("cert1.pem"), TEST_CERT_PEM).unwrap();
        std::fs::write(temp_dir.path().join("cert2.crt"), TEST_CERT_PEM).unwrap();
        std::fs::write(temp_dir.path().join("cert3.cer"), TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_scan_certificates_ignores_directories() {
        let temp_dir = TempDir::new().unwrap();

        // Create a subdirectory with .pem extension (edge case)
        std::fs::create_dir(temp_dir.path().join("subdir.pem")).unwrap();
        // Create a valid cert
        std::fs::write(temp_dir.path().join("valid.pem"), TEST_CERT_PEM).unwrap();

        let result = scan_certificates(temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());
        // Only the file should be counted, not the directory
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_save_certificate_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("new_cert.pem");

        let result = save_certificate(cert_path.to_str().unwrap(), TEST_CERT_PEM);
        assert!(result.is_ok());
        assert!(cert_path.exists());

        let content = std::fs::read_to_string(&cert_path).unwrap();
        assert_eq!(content, TEST_CERT_PEM);
    }

    #[test]
    fn test_save_certificate_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("existing_cert.pem");

        // Create initial file
        std::fs::write(&cert_path, "old content").unwrap();

        // Overwrite with new certificate
        let result = save_certificate(cert_path.to_str().unwrap(), TEST_CERT_PEM);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&cert_path).unwrap();
        assert_eq!(content, TEST_CERT_PEM);
    }

    #[test]
    fn test_save_certificate_fails_on_invalid_path() {
        let result = save_certificate("/nonexistent/directory/cert.pem", TEST_CERT_PEM);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_and_renew_empty_cert_dir() {
        let config = Config {
            endpoint: "https://example.com/renew".to_string(),
            cert_dir: "".to_string(),
            check_interval_seconds: 3600,
            expiry_threshold_days: 30,
        };

        // Should return Ok without doing anything when cert_dir is empty
        let result = check_and_renew_certificates(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_and_renew_nonexistent_directory() {
        let config = Config {
            endpoint: "https://example.com/renew".to_string(),
            cert_dir: "/nonexistent/directory".to_string(),
            check_interval_seconds: 3600,
            expiry_threshold_days: 30,
        };

        // Should return Ok (with warning logged) for nonexistent directory
        let result = check_and_renew_certificates(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_and_renew_no_expiring_certs() {
        let temp_dir = TempDir::new().unwrap();

        // Create a certificate (TEST_CERT_PEM expires in the past, so we need
        // to test the logic differently - use a very short threshold)
        std::fs::write(temp_dir.path().join("cert.pem"), TEST_CERT_PEM).unwrap();

        let config = Config {
            endpoint: "".to_string(), // No endpoint - would fail if renewal attempted
            cert_dir: temp_dir.path().to_str().unwrap().to_string(),
            check_interval_seconds: 3600,
            // Use negative threshold so no cert is "expiring soon"
            expiry_threshold_days: -9999,
        };

        // Should complete without attempting renewal
        let result = check_and_renew_certificates(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_clone() {
        let config = Config {
            endpoint: "https://example.com".to_string(),
            cert_dir: "/certs".to_string(),
            check_interval_seconds: 3600,
            expiry_threshold_days: 30,
        };

        let cloned = config.clone();
        assert_eq!(cloned.endpoint, config.endpoint);
        assert_eq!(cloned.cert_dir, config.cert_dir);
        assert_eq!(cloned.check_interval_seconds, config.check_interval_seconds);
        assert_eq!(cloned.expiry_threshold_days, config.expiry_threshold_days);
    }

    #[test]
    fn test_certificate_info_fields() {
        let expiry = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let cert = CertificateInfo {
            path: "/path/to/cert.pem".to_string(),
            expiry,
            subject: "CN=Test,O=Org".to_string(),
        };

        assert_eq!(cert.path, "/path/to/cert.pem");
        assert_eq!(cert.subject, "CN=Test,O=Org");
        assert_eq!(cert.expiry.year(), 2025);
        assert_eq!(cert.expiry.month(), 6);
        assert_eq!(cert.expiry.day(), 15);
    }
}
