//! Safe-match filters: identify *benign* placeholder/example/redacted strings
//! so they don't get treated as real secrets. When a rule matches, we log
//! which rule/explanation fired at `debug!` level.
//
// Usage:
//   if is_safe_match(bytes) { /* skip finding */ }
//
// If you also want the specific reason:
//   if let Some(reason) = is_safe_match_reason(bytes) {
//       // reason contains the rule description
//   }

use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tracing::debug;

/// A rule that describes *why* a match is considered safe/benign.
#[derive(Debug)]
struct SafeRule {
    /// Human-friendly reason that will be logged when this rule fires.
    description: &'static str,
    /// Compiled regex to detect the benign pattern.
    regex: Regex,
}

/// Compile a bytes regex and panic on failure (at init time).
fn compile(pattern: &'static str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| {
        // Compile happens once at startup, so panic is acceptable here.
        // We still emit a debug line to aid troubleshooting in non-panic logs.
        debug!("Failed to compile safe-list regex: {pattern}\nError: {e}");
        panic!("invalid safe-list regex: {pattern}: {e}");
    })
}

/// Case-insensitive patterns that indicate a *benign* match (placeholders, examples, redactions, etc.).
/// `is_safe_match()` returns true if any of these are present and logs which rule fired.
/// `is_safe_match_reason()` returns the matching rule's description instead of logging.
static SAFE_LIST_FILTER_RULES: Lazy<Vec<SafeRule>> = Lazy::new(|| {
    vec![
        SafeRule {
            description: "Assignment ending with EXAMPLEKEY (placeholder)",
            regex: compile(r"(?i)[:=][^:=]{0,64}EXAMPLEKEY"),
        },
        SafeRule {
            description: "AWS AKIA key explicitly marked as example/fake/test/sample",
            regex: compile(r"(?i)\b(AKIA(?:.*?EXAMPLE|.*?FAKE|TEST|.*?SAMPLE))\b"),
        },
        SafeRule {
            description: "Secret-like key followed by redaction marker (&&, ||, or ***** run)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\s(&&|\|\||\*{5,50})",
            ),
        },
        SafeRule {
            description: "Secret-like key + short value followed by another short assignment on same line (example-y)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b\w{4,12}\s{0,6}=\s{0,6}\D{0,3}\w{1,12}",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned from a shell variable reference (e.g., $FOO), not a literal",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\$\w{4,30}",
            ),
        },
        SafeRule {
            description: "Secret-like key set via randomness generator command (openssl rand ...), not a literal",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,16}[=:?][^=:?]{0,8}\bopenssl\s{0,4}rand\b",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned a value containing 'encrypted' (metadata/marker)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}encrypted",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned boolean literal (true/false)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(?:false|true)\b",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned to null-ish or self-referential placeholders",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(null|nil|none|password|pass|pwd|passwd|secret|cred|key|auth|authorization).{1,6}$",
            ),
        },
        SafeRule {
            description: "Classic xkcd fake password 'hunter2'",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}hunter2",
            ),
        },
        SafeRule {
            description: "Obvious placeholder sequences (123456789 or abcdefghij)",
            regex: compile(r"(?i)123456789|abcdefghij"),
        },
        SafeRule {
            description: "Literal placeholder tag '<secretmanager>'",
            regex: compile(r"(?i)<secretmanager>"),
        },
        SafeRule {
            description: "OpenAPI schema references near assignment/query (not a secret)",
            regex: compile(r"(?i)[=:?][^=:?]{0,8}#/components/schemas/"),
        },
        SafeRule {
            description: "Example MongoDB URI with placeholder user/pass like user:pass or foo:bar",
            regex: compile(
                r"(?i)\b(mongodb(?:\+srv)?://(?:user|foo)[^:@]+:(?:pass|bar)[^@]+@[-\w.%+/:]{3,64}(?:/\w+)?)",
            ),
        },
        SafeRule {
            description: "Classpath URI (configuration reference, not a secret)",
            regex: compile(r"(?i)\b(classpath://)"),
        },
        SafeRule {
            description: "Assignment using property placeholder like ${ENV_VAR}",
            regex: compile(r"(?i)(\b[^\s\t]{0,16}[=:][^$]*\$\{[a-z_-]{5,30}\})"),
        },
        SafeRule {
            description: "URL with basic auth to host ending in example/test (placeholder)",
            regex: compile(r"(?i)\b((?:https?:)?//[^:@]{3,50}:[^:@]{3,50}@[\w.]{0,16}(?:example|test))"),
        },
        SafeRule {
            description: "Assignment ending with SECRETMANAGER (explicit placeholder)",
            regex: compile(r"(?i)[:=][^:=]{0,32}\bSECRETMANAGER"),
        },
    ]
});

/// Returns `Some(&'static str)` with the rule description if the input likely
/// contains *benign* placeholder/test strings; otherwise `None`.
pub fn is_safe_match_reason(input: &[u8]) -> Option<&'static str> {
    SAFE_LIST_FILTER_RULES
        .iter()
        .find(|rule| rule.regex.is_match(input))
        .map(|rule| rule.description)
}

/// Returns true if the input likely contains *benign* placeholder/test strings,
/// and logs which rule triggered at `debug!` level.
pub fn is_safe_match(input: &[u8]) -> bool {
    if let Some(reason) = is_safe_match_reason(input) {
        debug!("Safe match: {reason}");
        true
    } else {
        false
    }
}
