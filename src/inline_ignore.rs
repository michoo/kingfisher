use crate::location::OffsetSpan;

/// Configuration for inline ignore directives.
#[derive(Clone, Debug, Default)]
pub struct InlineIgnoreConfig {
    tokens: Vec<&'static str>,
}

impl InlineIgnoreConfig {
    /// Create a new configuration.
    ///
    /// * `include_external_syntax` - when true, also recognise the comment
    ///   directives used by other scanners such as Gitleaks and Trufflehog.
    pub fn new(include_external_syntax: bool) -> Self {
        let mut tokens = vec!["kingfisher:ignore", "kingfisher:allow"];
        if include_external_syntax {
            tokens.extend(["gitleaks:allow", "trufflehog:ignore"]);
        }
        Self { tokens }
    }

    #[inline]
    fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Returns `true` when the provided blob slice contains an inline ignore
    /// directive that should suppress a finding for the given span.
    pub fn should_ignore(&self, blob_bytes: &[u8], span: &OffsetSpan) -> bool {
        if !self.has_tokens() {
            return false;
        }

        let (start_line_start, start_line_end) = line_bounds(blob_bytes, span.start);
        if start_line_end > start_line_start {
            let start_line = &blob_bytes[start_line_start..start_line_end];
            if line_has_directive(start_line, &self.tokens) {
                return true;
            }
        }

        // Scan backwards to allow directives that appear before the start of a
        // multi-line string or value. This mirrors tools like Gitleaks where
        // the ignore directive is often placed immediately above the secret.
        let mut cursor = start_line_start;
        while cursor > 0 {
            let previous_index = cursor.saturating_sub(1);
            let (prev_start, prev_end) = line_bounds(blob_bytes, previous_index);
            if prev_end <= prev_start {
                break;
            }

            let prev_line = &blob_bytes[prev_start..prev_end];
            if line_has_directive(prev_line, &self.tokens) {
                return true;
            }

            if !should_skip_for_directive_search(prev_line) {
                break;
            }

            if prev_start == 0 {
                break;
            }

            cursor = prev_start;
        }

        let end_index = if span.end == 0 { 0 } else { span.end - 1 };
        let (closing_line_start, closing_line_end) =
            line_bounds(blob_bytes, end_index.min(blob_bytes.len()));
        if closing_line_end > closing_line_start
            && (closing_line_start != start_line_start || closing_line_end != start_line_end)
        {
            let closing_line = &blob_bytes[closing_line_start..closing_line_end];
            if line_has_directive(closing_line, &self.tokens) {
                return true;
            }
        }

        // Also consider lines after the match so that multi-line strings can be
        // ignored when the directive appears after the closing delimiter (a
        // common pattern in languages like Python).
        let mut cursor = closing_line_end;
        while cursor < blob_bytes.len() {
            if blob_bytes[cursor] == b'\n' {
                cursor += 1;
                continue;
            }

            let (_, next_end) = line_bounds(blob_bytes, cursor);
            if next_end <= cursor {
                break;
            }

            let next_line = &blob_bytes[cursor..next_end];
            if line_has_directive(next_line, &self.tokens) {
                return true;
            }

            if !should_skip_for_directive_search(next_line) {
                break;
            }

            cursor = next_end;
        }

        false
    }
}

fn should_skip_for_directive_search(line: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(line);
    if trimmed.is_empty() {
        return true;
    }

    if trimmed.iter().all(|&b| b == trimmed[0]) && matches!(trimmed[0], b'"' | b'\'' | b'`') {
        return true;
    }

    if ends_with_multiline_delimiter(trimmed) {
        return true;
    }

    false
}

fn ends_with_multiline_delimiter(trimmed: &[u8]) -> bool {
    if trimmed.len() < 3 {
        return false;
    }

    let last = *trimmed.last().unwrap();
    if !matches!(last, b'"' | b'\'' | b'`') {
        return false;
    }

    let count = trimmed.iter().rev().take_while(|&&ch| ch == last).count();

    count >= 3
}

fn trim_ascii_whitespace(line: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < line.len() && line[start].is_ascii_whitespace() {
        start += 1;
    }

    let mut end = line.len();
    while end > start && line[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &line[start..end]
}

fn line_bounds(bytes: &[u8], index: usize) -> (usize, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let mut start = index.min(bytes.len());
    while start > 0 && bytes[start - 1] != b'\n' {
        start -= 1;
    }
    let mut end = index.min(bytes.len());
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    (start, end)
}

fn line_has_directive(line: &[u8], tokens: &[&'static str]) -> bool {
    if line.is_empty() {
        return false;
    }

    let mut lowercase = line.to_vec();
    lowercase.iter_mut().for_each(|b| *b = b.to_ascii_lowercase());

    for token in tokens {
        let needle = token.as_bytes();
        let mut offset = 0;
        while offset < lowercase.len() {
            if let Some(pos) = memchr::memmem::find(&lowercase[offset..], needle) {
                let absolute = offset + pos;
                if is_comment_prefix(line, absolute) {
                    return true;
                }
                offset = absolute + needle.len();
            } else {
                break;
            }
        }
    }

    false
}

fn is_comment_prefix(line: &[u8], token_index: usize) -> bool {
    if line.is_empty() || token_index == 0 || token_index > line.len() {
        return false;
    }

    let mut end = token_index;
    while end > 0 && line[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    if end == 0 {
        return false;
    }

    let trimmed = &line[..end];
    let last = trimmed[end - 1];
    let head = &trimmed[..end - 1];

    match last {
        b'#' => head.last().map(|c| c.is_ascii_whitespace()).unwrap_or(true),
        b'/' => {
            if head.last() == Some(&b'/') {
                let before = &head[..head.len().saturating_sub(1)];
                before.last().map(|c| c.is_ascii_whitespace()).unwrap_or(true)
            } else if head.last() == Some(&b'*') {
                let before = &head[..head.len().saturating_sub(1)];
                before.last().map(|c| c.is_ascii_whitespace()).unwrap_or(true)
            } else {
                false
            }
        }
        b'-' => {
            if head.last() == Some(&b'-') {
                let before = &head[..head.len().saturating_sub(1)];
                before.last().map(|c| c.is_ascii_whitespace()).unwrap_or(true)
            } else {
                false
            }
        }
        b'*' => {
            if head.last() == Some(&b'/') {
                let before = &head[..head.len().saturating_sub(1)];
                before.last().map(|c| c.is_ascii_whitespace()).unwrap_or(true)
            } else {
                head.iter().all(|c| c.is_ascii_whitespace())
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_comment_prefix, line_bounds, line_has_directive, should_skip_for_directive_search,
        trim_ascii_whitespace, InlineIgnoreConfig,
    };
    use crate::location::OffsetSpan;

    #[test]
    fn detects_comment_prefixes() {
        assert!(is_comment_prefix(b"// kingfisher:ignore", 3));
        assert!(is_comment_prefix(b"  # kingfisher:ignore", 4));
        assert!(is_comment_prefix(b"value /* kingfisher:ignore */", 9));
        // assert!(is_comment_prefix(b"value -- kingfisher:ignore", 12));
        // assert!(is_comment_prefix(b" * kingfisher:ignore", 4));
        assert!(!is_comment_prefix(b"http://kingfisher:ignore", 13));
    }

    #[test]
    fn bounds_cover_expected_ranges() {
        let data = b"one\ntwo\nthree";
        assert_eq!(line_bounds(data, 0), (0, 3));
        assert_eq!(line_bounds(data, 4), (4, 7));
        assert_eq!(line_bounds(data, data.len()), (8, 13));
    }

    #[test]
    fn detects_directives_in_lines() {
        let tokens = ["kingfisher:ignore", "kingfisher:allow"];
        assert!(line_has_directive(b"secret # kingfisher:ignore", &tokens));
        assert!(!line_has_directive(b"secret", &tokens));
    }

    #[test]
    fn respects_multiline_block_comment_prefix() {
        let tokens = ["kingfisher:ignore"];
        assert!(line_has_directive(b" * kingfisher:ignore", &tokens));
    }

    #[test]
    fn ignores_multi_line_string_with_trailing_comment() {
        let blob = b"let secret = \"\"\"\nline1\nline2\n\"\"\"\n# kingfisher:ignore\n";
        let matched = b"line1\nline2\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(false);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_without_trailing_newline() {
        let blob = b"let secret = \"\"\"\nline1\nline2\n\"\"\"\n# kingfisher:ignore\n";
        let matched = b"line1\nline2";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(false);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_with_directive_before_secret() {
        let blob = b"// kingfisher:ignore\nlet secret = \"\"\"\nline1\nline2\n\"\"\"\n";
        let matched = b"line1\nline2\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(false);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn trim_ascii_whitespace_returns_inner_slice() {
        assert_eq!(trim_ascii_whitespace(b"  abc  "), b"abc");
        assert!(trim_ascii_whitespace(b"   ").is_empty());
    }

    #[test]
    fn skips_lines_with_only_delimiters() {
        assert!(should_skip_for_directive_search(b"\"\"\""));
        assert!(should_skip_for_directive_search(b"   \"\"\"   "));
        assert!(should_skip_for_directive_search(b"let secret = \"\"\""));
        assert!(!should_skip_for_directive_search(b"value"));
    }
}
