//! `mirrorstack app module init <name>` — creates a fresh module
//! directory in CWD with a Go API skeleton, sql migrations stubs, and
//! a TS web frontend skeleton.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

mod templates;
mod validate;

pub fn run_init(name: &str) -> Result<()> {
    validate::name(name)?;

    // Try to create the root directory first; if it already exists,
    // refuse rather than scribbling files over a non-empty tree. This
    // sidesteps the TOCTOU pre-check `Path::exists()` would have made.
    match fs::create_dir(name) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(anyhow!("directory {name:?} already exists"));
        }
        Err(e) => return Err(e).with_context(|| format!("create dir {name}")),
    }

    println!("Creating module: {name}\n");
    let title = to_title(name);

    for (rel_path, content) in templates::files(name, &title) {
        let full = Path::new(name).join(&rel_path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
        }
        fs::write(&full, content).with_context(|| format!("write {}", full.display()))?;
        println!("  created {rel_path}");
    }

    println!("\nDone! Next steps:");
    println!("  cd {name}");
    println!("  mirrorstack dev");
    Ok(())
}

/// "my-cool-module" → "MyCoolModule"
fn to_title(name: &str) -> String {
    name.split('-')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            c.next()
                .map(|f| f.to_uppercase().chain(c).collect::<String>())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_title_simple() {
        assert_eq!(to_title("foo"), "Foo");
    }

    #[test]
    fn to_title_hyphenated() {
        assert_eq!(to_title("my-cool-module"), "MyCoolModule");
    }

    #[test]
    fn to_title_handles_empty_segments() {
        assert_eq!(to_title("foo--bar"), "FooBar");
        assert_eq!(to_title(""), "");
    }
}
