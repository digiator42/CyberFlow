//! Pattern-matching signatures.
//!
//! Deliberately substring-based (lowercased) instead of pulling in a `regex`
//! engine: WAF-style signatures are overwhelmingly literal markers, and a
//! case-insensitive `contains` is both smaller in the wasm binary and immune
//! to regex-DoS on hostile log content.

use super::{Detection, Severity};

/// One detection rule: any lowercased needle appearing in the payload trips it.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub needles: &'static [&'static str],
}

/// The signature set. Ordered so the most specific finding lands first.
pub static RULES: &[Rule] = &[
    Rule {
        id: "traversal.path",
        title: "Directory traversal attempt",
        severity: Severity::High,
        needles: &["../", "..\\", "..%2f", "%2e%2e%2f", "/..;/"],
    },
    Rule {
        id: "sqli.boolean",
        title: "SQL injection (boolean tautology)",
        severity: Severity::Critical,
        needles: &[
            "or 1=1",
            "or '1'='1",
            "\" or \"1\"=\"1",
            "or 2=2",
            "') or ('",
            "admin' --",
            "' or ''='",
        ],
    },
    Rule {
        id: "sqli.query",
        title: "SQL injection (query manipulation)",
        severity: Severity::Critical,
        needles: &[
            "union select",
            "drop table",
            "insert into",
            "xp_cmdshell",
            "information_schema",
        ],
    },
    Rule {
        id: "xss.script",
        title: "Cross-site scripting (<script>)",
        severity: Severity::High,
        needles: &["<script", "</script", "javascript:", "onerror=", "onload="],
    },
    Rule {
        id: "shell.reverse",
        title: "Reverse shell / command injection",
        severity: Severity::Critical,
        needles: &[
            "/bin/sh -i",
            "/bin/bash -i",
            "bash -i >& /dev/tcp",
            "nc -e /bin",
            "python -c 'import socket",
            "cmd.exe /c",
        ],
    },
    Rule {
        id: "scanner.tool",
        title: "Automated vulnerability scanner",
        severity: Severity::High,
        needles: &[
            "sqlmap",
            "nikto",
            "nessus",
            "nmap scripting",
            "gobuster",
            "dirbuster",
            "wpscan",
            "acunetix",
        ],
    },
];

/// Scan a payload against every rule; returns all hits.
pub fn scan(payload: &str) -> Vec<Detection> {
    let hay = payload.to_ascii_lowercase();
    RULES
        .iter()
        .filter(|rule| rule.needles.iter().any(|n| hay.contains(n)))
        .map(|rule| Detection {
            rule_id: rule.id,
            title: rule.title,
            severity: rule.severity,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_id(payload: &str) -> Option<&'static str> {
        scan(payload).first().map(|d| d.rule_id)
    }

    #[test]
    fn matches_are_case_insensitive() {
        assert_eq!(
            first_id("GET /<SCRIPT>alert(1)</SCRIPT>"),
            Some("xss.script")
        );
        assert_eq!(
            first_id("/browse?file=..%2f..%2fetc%2fpasswd"),
            Some("traversal.path")
        );
    }

    #[test]
    fn multiple_rules_can_trip_one_payload() {
        let hits = scan("sqlmap UNION SELECT password FROM users");
        assert!(hits.iter().any(|h| h.rule_id == "sqli.query"));
        assert!(hits.iter().any(|h| h.rule_id == "scanner.tool"));
    }

    #[test]
    fn benign_payload_is_clean() {
        assert!(scan("GET /api/v1/users?page=2&sort=name HTTP/1.1 200").is_empty());
        assert!(scan("payment settled, invoice #4471").is_empty());
    }

    #[test]
    fn severities_are_ordered_by_danger() {
        let sqli = scan("or 1=1").pop().unwrap();
        assert_eq!(sqli.severity, Severity::Critical);
        let scanner = scan("nikto/2.5.0").pop().unwrap();
        assert_eq!(scanner.severity, Severity::High);
    }
}
