// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Policy configuration loading and validation
//!
//! Supports loading network policies from JSON or YAML configuration files.
//! Provides validation with clear error messages for invalid configs.

use crate::manager::NetworkManager;
use crate::policy::{HostRule, HostSpec, NetworkPolicy};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use thiserror::Error;

// =============================================================================
// Configuration Error
// =============================================================================

/// Errors that can occur when loading or validating configuration
///
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Reserved for future validation (not currently constructed)
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Reserved for future validation (not currently constructed)
    #[error("Invalid port: {port} (must be 0-65535)")]
    InvalidPort { port: u16 },

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid CIDR prefix in {cidr}: {reason}")]
    InvalidCidrPrefix { cidr: String, reason: String },

    #[error("Invalid wildcard pattern: {pattern} ({reason})")]
    InvalidWildcard { pattern: String, reason: String },

    /// Reserved for future validation (not currently constructed)
    #[error("Empty allowlist with fail-closed policy will block all traffic")]
    EmptyAllowlist,
}

// =============================================================================
// Policy Configuration Format
// =============================================================================

/// Complete network policy configuration (JSON/YAML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Policy version (for config management)
    #[serde(default = "default_version")]
    pub version: u32,

    /// Policy name/description
    #[serde(default)]
    pub name: Option<String>,

    /// Host rules
    #[serde(default)]
    pub rules: Vec<HostRuleConfig>,

    /// Allow ICMP traffic
    #[serde(default)]
    pub allow_icmp: bool,
}

const fn default_version() -> u32 {
    1
}

/// Fluent builder for `PolicyConfig`.
#[derive(Debug, Clone)]
#[must_use]
pub struct PolicyConfigBuilder {
    config: PolicyConfig,
}

impl Default for PolicyConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyConfigBuilder {
    /// Start a builder with fail-closed defaults.
    pub const fn new() -> Self {
        Self {
            config: PolicyConfig {
                version: default_version(),
                name: None,
                rules: Vec::new(),
                allow_icmp: false,
            },
        }
    }

    /// Set policy name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = Some(name.into());
        self
    }

    /// Allow ICMP traffic.
    pub const fn allow_icmp(mut self, allow: bool) -> Self {
        self.config.allow_icmp = allow;
        self
    }

    /// Allow ICMP traffic (convenience).
    pub const fn enable_icmp(self) -> Self {
        self.allow_icmp(true)
    }

    /// Add a host rule for a single port.
    pub fn allow_host_port(mut self, host: impl Into<String>, port: u16) -> Self {
        self.config.rules.push(HostRuleConfig {
            host: host.into(),
            ports: vec![port],
            comment: None,
        });
        self
    }

    /// Add a host rule for multiple ports.
    pub fn allow_host_ports(mut self, host: impl Into<String>, ports: &[u16]) -> Self {
        self.config.rules.push(HostRuleConfig {
            host: host.into(),
            ports: ports.to_vec(),
            comment: None,
        });
        self
    }

    /// Add a host rule using a `HostSpec`.
    pub fn allow_host_spec(mut self, host: &HostSpec, ports: &[u16]) -> Self {
        self.config.rules.push(HostRuleConfig {
            host: host.to_host_string(),
            ports: ports.to_vec(),
            comment: None,
        });
        self
    }

    /// Add a host rule using a `HostSpec` with a comment.
    pub fn allow_host_spec_with_comment(
        mut self,
        host: &HostSpec,
        ports: &[u16],
        comment: impl Into<String>,
    ) -> Self {
        self.config.rules.push(HostRuleConfig {
            host: host.to_host_string(),
            ports: ports.to_vec(),
            comment: Some(comment.into()),
        });
        self
    }

    /// Add a host rule with a comment.
    pub fn allow_host_ports_with_comment(
        mut self,
        host: impl Into<String>,
        ports: &[u16],
        comment: impl Into<String>,
    ) -> Self {
        self.config.rules.push(HostRuleConfig {
            host: host.into(),
            ports: ports.to_vec(),
            comment: Some(comment.into()),
        });
        self
    }

    /// Build the policy config with validation.
    pub fn build(self) -> Result<PolicyConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

/// Host rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuleConfig {
    /// Host (IP address, domain, or CIDR notation)
    pub host: String,

    /// Allowed ports
    pub ports: Vec<u16>,

    /// Optional comment
    #[serde(default)]
    pub comment: Option<String>,
}

// =============================================================================
// Configuration Loading
// =============================================================================

impl PolicyConfig {
    /// Create a fluent policy config builder.
    pub const fn builder() -> PolicyConfigBuilder {
        PolicyConfigBuilder::new()
    }

    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, ConfigError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate host rules
        for rule in &self.rules {
            // Note: port 0 is valid — it means "all ports" (wildcard).
            // See policy.rs HostRule::matches_ip() for wildcard semantics.

            // Validate host format
            Self::validate_host_spec(&rule.host)?;
        }

        // Warn if allowlist is empty with fail-closed
        if self.rules.is_empty() {
            log::warn!("Empty host rules with deny default - all traffic will be blocked");
        }

        // Warn if all rules are domain-based (inoperative at IP layer)
        if !self.rules.is_empty()
            && self
                .rules
                .iter()
                .all(|r| r.host.parse::<IpAddr>().is_err() && !r.host.contains('/'))
        {
            log::warn!(
                "All {} host rules are domain-based. Domain rules are not enforced at the \
                 IP/port layer (they require protocol inspectors). With deny default, all \
                 IP traffic will be blocked. Add IP or subnet rules for IP-level enforcement.",
                self.rules.len()
            );
        }

        Ok(())
    }

    /// Validate a host specification
    fn validate_host_spec(host: &str) -> Result<(), ConfigError> {
        // Check for CIDR notation
        if host.contains('/') {
            let parts: Vec<&str> = host.split('/').collect();
            if parts.len() != 2 {
                return Err(ConfigError::InvalidIpAddress(host.to_string()));
            }
            let ip: IpAddr = parts[0]
                .parse()
                .map_err(|_| ConfigError::InvalidIpAddress(format!("{host} (invalid IP)")))?;
            // Validate prefix
            let prefix: u8 = parts[1]
                .parse()
                .map_err(|_| ConfigError::InvalidIpAddress(format!("{host} (invalid prefix)")))?;
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_prefix {
                return Err(ConfigError::InvalidIpAddress(format!(
                    "{host} (prefix must be <= {max_prefix})"
                )));
            }
            return Ok(());
        }

        // Check for wildcard domain
        if host.contains('*') {
            return Self::validate_wildcard_pattern(host);
        }

        // Check for IP address
        if host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        // Assume it's a domain name - basic validation
        if host.is_empty() {
            return Err(ConfigError::InvalidConfig("Empty host".to_string()));
        }

        Ok(())
    }

    /// Validate a wildcard pattern
    fn validate_wildcard_pattern(pattern: &str) -> Result<(), ConfigError> {
        if pattern.is_empty() {
            return Err(ConfigError::InvalidWildcard {
                pattern: pattern.to_string(),
                reason: "empty pattern".to_string(),
            });
        }

        // Check for invalid wildcards like **.example.com or *example.com
        if pattern.contains("**") {
            return Err(ConfigError::InvalidWildcard {
                pattern: pattern.to_string(),
                reason: "double wildcard not allowed".to_string(),
            });
        }

        // Wildcard must be at the start followed by a dot
        if pattern.contains('*') && !pattern.starts_with("*.") && pattern != "*" {
            return Err(ConfigError::InvalidWildcard {
                pattern: pattern.to_string(),
                reason: "wildcard must be '*.domain' format".to_string(),
            });
        }

        Ok(())
    }

    /// Convert to `NetworkPolicy`
    ///
    /// **Note:** Domain-based host rules (e.g., "api.openai.com") will be
    /// included in the policy but will NOT match IP traffic at the
    /// `PolicyNetBackend` level. Domain rules require protocol inspector
    /// integration (DNS/TLS) to be effective. See [`HostSpec::Domain`] docs.
    pub fn to_network_policy(&self) -> Result<NetworkPolicy, ConfigError> {
        self.validate()?;

        let mut builder = NetworkPolicy::builder()
            .allow_icmp(self.allow_icmp)
            .version(self.version);

        if let Some(ref name) = self.name {
            builder = builder.name(name.clone());
        }

        let mut has_domain_rules = false;
        for rule in &self.rules {
            let host_spec = Self::parse_host_spec(&rule.host)?;
            if matches!(host_spec, HostSpec::Domain(_)) {
                has_domain_rules = true;
            }
            let ports: HashSet<u16> = rule.ports.iter().copied().collect();
            builder = builder.allow_host_rule(HostRule {
                host: host_spec,
                ports,
                comment: rule.comment.clone(),
            });
        }

        if has_domain_rules {
            log::warn!(
                "Policy contains domain-based host rules which will NOT match IP traffic \
                 in PolicyNetBackend. Domain rules require stream evidence from DNS, TLS, \
                 or HTTP before they authorize a flow."
            );
        }

        Ok(builder.build())
    }

    /// Parse a host specification string
    fn parse_host_spec(host: &str) -> Result<HostSpec, ConfigError> {
        // Check for CIDR notation
        if let Some((addr, prefix)) = host.split_once('/') {
            if addr.is_empty() || prefix.is_empty() || prefix.contains('/') {
                return Err(ConfigError::InvalidIpAddress(host.to_string()));
            }
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| ConfigError::InvalidIpAddress(host.to_string()))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| ConfigError::InvalidIpAddress(host.to_string()))?;
            return HostSpec::try_subnet(ip, prefix).map_err(|err| {
                ConfigError::InvalidCidrPrefix {
                    cidr: host.to_string(),
                    reason: err.to_string(),
                }
            });
        }

        // Check for IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(HostSpec::Ip(ip));
        }

        // Assume domain
        Ok(HostSpec::Domain(host.to_string()))
    }

    /// Create a packet-admission [`NetworkManager`] from this config.
    ///
    /// The config surface contains only policy enforced by this crate. HTTP,
    /// DNS, TLS, and MITM policy must be represented through stream evidence
    /// and trusted interceptors, not inert serde fields.
    pub fn to_network_manager(&self) -> Result<NetworkManager, ConfigError> {
        let policy = self.to_network_policy()?;
        Ok(NetworkManager::new(policy.to_packet_policy()))
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            version: 1,
            name: None,
            rules: Vec::new(),
            allow_icmp: false,
        }
    }
}

// =============================================================================
// Example Configurations
// =============================================================================

/// Create an example policy for AI agent network access
///
/// **Note:** The domain-based rules (e.g., "api.openai.com") demonstrate the
/// configuration format but will NOT match IP-level traffic in `PolicyNetBackend`
/// on their own. They require stream evidence from DNS, SNI, or HTTP parsing.
/// Only the IP-based rule ("8.8.8.8") will enforce at the packet level.
pub fn example_ai_agent_policy() -> PolicyConfig {
    PolicyConfig {
        version: 1,
        name: Some("AI Agent Network Policy".to_string()),
        rules: vec![
            // NOTE: Domain rules require stream evidence to match traffic.
            // They are included here to demonstrate the configuration format
            // and for use with DNS/SNI/HTTP policy.
            HostRuleConfig {
                host: "api.openai.com".to_string(),
                ports: vec![443],
                comment: Some("OpenAI API (requires stream evidence)".to_string()),
            },
            HostRuleConfig {
                host: "*.github.com".to_string(),
                ports: vec![443],
                comment: Some("GitHub API and repos (requires stream evidence)".to_string()),
            },
            // IP-based rules enforce at the packet level without inspectors.
            HostRuleConfig {
                host: "8.8.8.8".to_string(),
                ports: vec![53],
                comment: Some("Google DNS".to_string()),
            },
        ],
        allow_icmp: false,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_load_json_config() {
        let json = r#"{
            "version": 1,
            "name": "test-policy",
            "rules": [
                {"host": "api.openai.com", "ports": [443]},
                {"host": "8.8.8.8", "ports": [53]}
            ],
            "allow_icmp": false
        }"#;

        let config = PolicyConfig::from_json(json).unwrap();
        assert_eq!(config.name, Some("test-policy".to_string()));
        assert_eq!(config.rules.len(), 2);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let original = example_ai_agent_policy();
        let json = original.to_json().unwrap();
        let parsed = PolicyConfig::from_json(&json).unwrap();

        assert_eq!(original.name, parsed.name);
        assert_eq!(original.rules.len(), parsed.rules.len());
    }

    #[test]
    fn test_validate_port_zero_wildcard() {
        // Port 0 means "all ports" — must be accepted by validation
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.2.2".to_string(),
                ports: vec![0],
                comment: None,
            }],
            ..Default::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.0.0/99".to_string(), // Invalid prefix
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_to_network_policy() {
        let config = PolicyConfig::builder()
            .enable_icmp()
            .allow_host_ports("192.168.1.0/24", &[22, 80])
            .allow_host_ports("8.8.8.8", &[53])
            .build()
            .unwrap();

        let policy = config.to_network_policy().unwrap();
        assert!(policy.allow_icmp);
        assert_eq!(policy.rules.len(), 2);

        // Subnet rule should match
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 100), 22));
        // IP rule should match
        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        // Unknown should deny
        assert!(!policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
    }

    #[test]
    fn test_to_network_manager() {
        let config = example_ai_agent_policy();
        let manager = config.to_network_manager().unwrap();

        assert_eq!(
            manager.packet_policy().name,
            Some("AI Agent Network Policy".to_string())
        );
        assert!(
            manager
                .packet_policy()
                .rules
                .iter()
                .any(|rule| !matches!(rule.host, HostSpec::Domain(_)))
        );
        assert!(
            !manager
                .packet_policy()
                .rules
                .iter()
                .any(|rule| matches!(rule.host, HostSpec::Domain(_)))
        );
    }

    #[test]
    fn test_to_network_policy_port_zero_wildcard() {
        // Port 0 = wildcard "all ports"; config → policy conversion must work
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.2.2".to_string(),
                ports: vec![0],
                comment: None,
            }],
            ..Default::default()
        };
        let policy = config.to_network_policy().expect("port 0 should be valid");
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.rules[0].ports.contains(&0));
    }

    #[test]
    fn test_to_network_policy_rejects_invalid_prefix() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.0.0/99".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        let result = config.to_network_policy();
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config_is_fail_closed() {
        let config = PolicyConfig::default();
        assert!(!config.allow_icmp);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_example_policy_validates() {
        let config = example_ai_agent_policy();
        assert!(config.validate().is_ok());
    }

    // =========================================================================
    // Builder coverage
    // =========================================================================

    #[test]
    fn test_builder_name() {
        let config = PolicyConfig::builder()
            .name("my-policy")
            .allow_host_port("example.com", 443)
            .build()
            .unwrap();
        assert_eq!(config.name, Some("my-policy".to_string()));
    }

    #[test]
    fn test_builder_allow_host_spec() {
        let spec = HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let config = PolicyConfig::builder()
            .allow_host_spec(&spec, &[53])
            .build()
            .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].host, "8.8.8.8");
    }

    #[test]
    fn test_builder_allow_host_spec_with_comment() {
        let spec = HostSpec::Domain("example.com".to_string());
        let config = PolicyConfig::builder()
            .allow_host_spec_with_comment(&spec, &[80, 443], "Web server")
            .build()
            .unwrap();
        assert_eq!(config.rules[0].comment, Some("Web server".to_string()));
    }

    #[test]
    fn test_builder_allow_host_ports_with_comment() {
        let config = PolicyConfig::builder()
            .allow_host_ports_with_comment("example.com", &[80, 443], "HTTP/HTTPS")
            .build()
            .unwrap();
        assert_eq!(config.rules[0].ports, vec![80, 443]);
        assert_eq!(config.rules[0].comment, Some("HTTP/HTTPS".to_string()));
    }

    #[test]
    fn test_builder_default_is_default() {
        let builder = PolicyConfigBuilder::default();
        let config = builder.allow_host_port("example.com", 443).build().unwrap();
        assert!(!config.allow_icmp);
    }

    // =========================================================================
    // Validation edge cases
    // =========================================================================

    #[test]
    fn test_validate_wildcard_star_only() {
        // Single "*" is valid
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "*".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_wildcard_without_dot() {
        // "*example.com" is invalid (must be "*.example.com")
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "*example.com".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_wildcard() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: String::new(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_host_wildcards() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "**bad.com".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_host() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: String::new(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_host_spec_wildcard_domain() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "*.example.com".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_host_spec_ipv6() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "::1".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_cidr_ipv6() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "fd00::/64".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_cidr_ipv6_prefix_too_large() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "fd00::/200".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_cidr_bad_ip() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "not-an-ip/24".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_cidr_bad_prefix() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.0.0/abc".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_cidr_triple_slash() {
        let config = PolicyConfig {
            rules: vec![HostRuleConfig {
                host: "10.0.0.0/24/extra".to_string(),
                ports: vec![443],
                comment: None,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    // =========================================================================
    // parse_host_spec coverage
    // =========================================================================

    #[test]
    fn test_parse_host_spec_domain() {
        let config = PolicyConfig::builder()
            .allow_host_port("api.example.com", 443)
            .build()
            .unwrap();
        let policy = config.to_network_policy().unwrap();
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_parse_host_spec_ipv6_cidr() {
        let config = PolicyConfig::builder()
            .allow_host_ports("fd00::/64", &[443])
            .build()
            .unwrap();
        let policy = config.to_network_policy().unwrap();
        assert_eq!(policy.rules.len(), 1);
    }

    // =========================================================================
    // to_network_manager produces a packet manager only
    // =========================================================================

    #[test]
    fn test_to_network_manager_minimal() {
        let config = PolicyConfig::builder()
            .allow_host_port("example.com", 443)
            .build()
            .unwrap();
        let manager = config.to_network_manager().unwrap();
        assert_eq!(manager.packet_policy().rules.len(), 0);
    }

    // =========================================================================
    // ConfigError Display and JSON error
    // =========================================================================

    #[test]
    fn test_config_error_json() {
        let result = PolicyConfig::from_json("{invalid json}");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("JSON"));
    }

    #[test]
    fn test_config_error_invalid_port_display() {
        let e = ConfigError::InvalidPort { port: 0 };
        assert!(e.to_string().contains('0'));
    }

    #[test]
    fn test_config_error_empty_allowlist_display() {
        let e = ConfigError::EmptyAllowlist;
        assert!(e.to_string().contains("block all traffic"));
    }

    #[test]
    fn test_config_error_invalid_wildcard_display() {
        let e = ConfigError::InvalidWildcard {
            pattern: "**x".to_string(),
            reason: "double wildcard".to_string(),
        };
        assert!(e.to_string().contains("**x"));
        assert!(e.to_string().contains("double wildcard"));
    }

    #[test]
    fn test_config_error_validation_display() {
        let e = ConfigError::ValidationError("test reason".to_string());
        assert!(e.to_string().contains("test reason"));
    }

    #[test]
    fn test_config_error_invalid_config_display() {
        let e = ConfigError::InvalidConfig("bad config".to_string());
        assert!(e.to_string().contains("bad config"));
    }

    #[test]
    fn test_config_error_invalid_ip_display() {
        let e = ConfigError::InvalidIpAddress("not-ip".to_string());
        assert!(e.to_string().contains("not-ip"));
    }

    // =========================================================================
    // JSON edge cases
    // =========================================================================

    #[test]
    fn test_from_json_defaults() {
        // Minimal JSON — all optional fields use defaults
        let json = r#"{"rules": [{"host": "example.com", "ports": [443]}]}"#;
        let config = PolicyConfig::from_json(json).unwrap();
        assert_eq!(config.version, 1);
        assert!(!config.allow_icmp);
        assert!(config.name.is_none());
    }

    #[test]
    fn test_from_json_rejects_inert_security_fields() {
        for field in ["default_action", "http", "dns", "tls"] {
            let json = format!(
                r#"{{
                    "rules": [{{"host": "example.com", "ports": [443]}}],
                    "{field}": {{}}
                }}"#
            );
            assert!(
                PolicyConfig::from_json(&json).is_err(),
                "field {field} must not be silently accepted"
            );
        }
    }

    #[test]
    fn test_to_json_roundtrip_builder() {
        let config = PolicyConfig::builder()
            .name("test")
            .enable_icmp()
            .allow_host_port("1.2.3.4", 80)
            .build()
            .unwrap();
        let json = config.to_json().unwrap();
        let parsed = PolicyConfig::from_json(&json).unwrap();
        assert_eq!(parsed.name, Some("test".to_string()));
        assert!(parsed.allow_icmp);
    }
}
