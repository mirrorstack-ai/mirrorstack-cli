//! Polling file watcher for `dev --all` hot-reload.
//!
//! Mirrors the air config the shell runner generated: watch `.go` and
//! `.sql`, exclude `tmp`, `web`, `node_modules`, and POLL mtimes rather
//! than using native fs events — OrbStack/Docker bind mounts deliver no
//! inotify events, so a native watcher would silently miss every edit.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

const WATCH_EXTS: &[&str] = &["go", "sql"];
const EXCLUDE_DIRS: &[&str] = &["tmp", "web", "node_modules", ".git"];

/// Sorted (path, mtime) list of every watched file under `dir`. Two scans
/// compare equal iff no watched file was added, removed, or modified.
pub(super) type Signature = Vec<(PathBuf, SystemTime)>;

pub(super) fn scan(dir: &Path) -> Signature {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Signature) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let path = entry.path();
        if ft.is_dir() {
            let name = entry.file_name();
            if EXCLUDE_DIRS.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            walk(&path, out);
        } else if ft.is_file() {
            let watched = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| WATCH_EXTS.contains(&e));
            if !watched {
                continue;
            }
            if let Ok(md) = entry.metadata() {
                out.push((path, md.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scan_includes_watched_extensions_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), "package main").unwrap();
        std::fs::create_dir(tmp.path().join("sql")).unwrap();
        std::fs::write(tmp.path().join("sql/0001.sql"), "select 1").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), "ignored").unwrap();

        let sig = scan(tmp.path());
        let names: Vec<_> = sig
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["main.go", "0001.sql"], "got {names:?}");
    }

    #[test]
    fn scan_skips_excluded_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), "package main").unwrap();
        for dir in ["web", "tmp", "node_modules"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
            std::fs::write(tmp.path().join(dir).join("skip.go"), "x").unwrap();
        }
        assert_eq!(scan(tmp.path()).len(), 1);
    }

    #[test]
    fn signature_changes_on_touch_add_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let main_go = tmp.path().join("main.go");
        std::fs::write(&main_go, "package main").unwrap();
        let before = scan(tmp.path());

        // Touch: bump mtime without changing content or file set.
        let f = std::fs::File::options().write(true).open(&main_go).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(2))
            .unwrap();
        let touched = scan(tmp.path());
        assert_ne!(before, touched, "mtime bump must change the signature");

        // Add.
        std::fs::write(tmp.path().join("extra.go"), "package main").unwrap();
        let added = scan(tmp.path());
        assert_ne!(touched, added);

        // Remove.
        std::fs::remove_file(tmp.path().join("extra.go")).unwrap();
        assert_eq!(scan(tmp.path()).len(), 1);
    }
}
