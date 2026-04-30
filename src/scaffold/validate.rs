use anyhow::{Result, anyhow};

/// `^[a-z][a-z0-9-]*$`, length 2..=40. Matches the Go reference impl
/// (scaffold/validate.go in the previous Go CLI).
pub fn name(s: &str) -> Result<()> {
    let len = s.chars().count();
    if !(2..=40).contains(&len) {
        return Err(anyhow!("module name must be 2-40 characters, got {len}"));
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(anyhow!(
            "module name must start with a lowercase letter (e.g., my-analytics)"
        ));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(anyhow!(
                "module name must be lowercase alphanumeric with hyphens (e.g., my-analytics)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for n in ["my-mod", "ab", "abcdef", "a1-b2-c3"] {
            assert!(name(n).is_ok(), "expected {n:?} to be valid");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for n in [
            "a",            // too short
            "Foo",          // uppercase first
            "1foo",         // leading digit
            "foo_bar",      // underscore
            "foo bar",      // space
            "-foo",         // leading hyphen
        ] {
            assert!(name(n).is_err(), "expected {n:?} to be invalid");
        }
    }
}
