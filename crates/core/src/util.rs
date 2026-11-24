//! Small path-classification helpers shared by adapters and the engine.

/// True for virtual/tool URI paths like `xd://mcp__dart_dtd` or `file:///tmp`.
/// Such values are display strings, not workspace-relative paths, and must
/// never be joined onto a project root.
pub fn is_uri_path(path: &str) -> bool {
    let Some((scheme, _)) = path.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_uris_vs_paths() {
        assert!(is_uri_path("xd://mcp__dart_dtd"));
        assert!(is_uri_path("https://example.com/x"));
        assert!(!is_uri_path("lib/main.dart"));
        assert!(!is_uri_path("src/xd:/weird"));
        assert!(!is_uri_path("://no-scheme"));
    }
}
