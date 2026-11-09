//! The `webinfo` plugin: one JSON document kept in `file`, which AtomDNS's
//! WebUI read and replaced at the plugin's own `/plugins/<tag>` path (client
//! names). atom fork: that route and the WebUI were removed in atom step 6; the
//! plugin still loads (a configuration that declares it keeps working, and an
//! invalid document is still refused), but nothing reads the document.
//!
//! The reference host's JSON escaping ([`escape_html`]) is shared with
//! `requery`.

use std::path::PathBuf;

/// The runtime owner of one `webinfo` plugin.
pub struct WebInfo {
    pub tag: String,
}

impl WebInfo {
    /// Reads `file`: a missing or empty file is an empty object, an invalid
    /// document is an error.
    pub(crate) fn load(tag: &str, file: PathBuf) -> Result<Self, String> {
        match std::fs::read(&file) {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(bytes) => {
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
                    format!("failed to parse json from file {}: {error}", file.display())
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to read {}: {error}", file.display())),
        }
        Ok(Self {
            tag: tag.to_owned(),
        })
    }
}

/// Go's JSON encoder escapes these characters inside strings; none of them
/// can occur outside a string in valid JSON text.
pub(crate) fn escape_html(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for character in json.chars() {
        match character {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_matches_the_reference_encoder() {
        assert_eq!(
            escape_html(r#"{"b":"<x&y>"}"#),
            "{\"b\":\"\\u003cx\\u0026y\\u003e\"}"
        );
    }
}
