//! Shannon-entropy screening for obfuscated payloads.
//!
//! Base64-encoded reverse shells, exfiltrated blobs, and minified JS all
//! share a signature: long, whitespace-free, high-entropy text. A normal
//! sentence or URL never qualifies because spaces and structure drag entropy
//! down.

use super::{Detection, Severity};

/// Minimum payload length before entropy is even considered.
pub const MIN_LEN: usize = 64;
/// Bits-per-character threshold. Random base64 sits near 5.9; English prose
/// with spaces sits near 4.0 and is additionally excluded by the whitespace
/// rule below.
pub const ENTROPY_THRESHOLD: f64 = 4.6;

/// Shannon entropy of a byte slice, in bits per character.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// True when the payload looks like an encoded/obfuscated blob.
pub fn looks_obfuscated(s: &str) -> bool {
    if s.len() < MIN_LEN {
        return false;
    }
    // Structured text (sentences, JSON, URLs) contains whitespace; encoded
    // blobs do not.
    if s.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    shannon_entropy(s.as_bytes()) >= ENTROPY_THRESHOLD
}

/// Screen a payload; returns at most one entropy finding.
pub fn check(payload: &str) -> Vec<Detection> {
    // Trim surrounding quotes/whitespace first — a JSON-encoded blob still
    // counts even though the envelope has a little structure.
    let trimmed = payload.trim().trim_matches('"');
    if looks_obfuscated(trimmed) {
        vec![Detection {
            rule_id: "entropy.obfuscated",
            title: "High-entropy payload (possible encoded shell)",
            severity: Severity::High,
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_bytes_is_maximal() {
        // 256 distinct byte values → log2(256) = 8 bits.
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_single_repeated_byte_is_zero() {
        assert_eq!(shannon_entropy(&[b'a'; 100]), 0.0);
    }

    #[test]
    fn detects_long_base64_blob() {
        // Deterministic pseudo-random base64 (~5.9 bits/char, no whitespace).
        let blob: String = (0..160u32)
            .map(|i| {
                const ALPHABET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                ALPHABET[((i.wrapping_mul(2654435761)) >> 7) as usize % 64] as char
            })
            .collect();
        assert!(
            looks_obfuscated(&blob),
            "entropy={}",
            shannon_entropy(blob.as_bytes())
        );
        assert!(!check(&blob).is_empty());
    }

    #[test]
    fn ignores_ordinary_text_even_when_long() {
        let sentence = "GET /api/v1/orders?page=3&sort=created_at returned 200 in 42ms for user session token refresh".repeat(2);
        assert!(!looks_obfuscated(&sentence));
        assert!(check(&sentence).is_empty());
    }

    #[test]
    fn ignores_short_payloads() {
        assert!(!looks_obfuscated("aGVsbG8gd29ybGQ="));
    }
}
