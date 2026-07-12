//! Next.js standalone (SSR) build detection + packaging.
//!
//! Mirrors web-applications' own CI "Package standalone bundle" step
//! (`.github/workflows/publish.yml`) shape-for-shape: `cp -r
//! .next/standalone/. pkg/`, `mkdir -p pkg/.next && cp -r .next/static
//! pkg/.next/static`, write an executable `run.sh` launcher, hard-fail on
//! any symlink found in the result, then zip `pkg/`'s contents (not `pkg/`
//! itself) into a single archive for upload.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use tempfile::TempDir;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// `#!/bin/bash\nexec node server.js\n` — the Lambda Web Adapter entrypoint,
/// verbatim from web-applications' own CI packaging step.
const RUN_SH: &str = "#!/bin/bash\nexec node server.js\n";

/// True when `dir` looks like a Next.js standalone SSR build output (a
/// `.next/standalone` subdirectory is present) rather than a static
/// `out/`-style export.
pub fn looks_like_standalone(dir: &Path) -> bool {
    dir.join(".next").join("standalone").is_dir()
}

/// Package `.next/standalone` + `.next/static` + a `run.sh` launcher from
/// `build_dir` into a zip file, matching web-applications' CI shape
/// exactly. Returns the backing temp directory (keep it alive until the
/// upload of the returned path completes) and the zip file's path.
pub fn package_bundle(build_dir: &Path) -> Result<(TempDir, PathBuf)> {
    let standalone = build_dir.join(".next").join("standalone");
    let static_dir = build_dir.join(".next").join("static");
    if !standalone.is_dir() {
        return Err(anyhow!(
            "{} has no .next/standalone — build with `output: \"standalone\"` in next.config first",
            build_dir.display()
        ));
    }
    if !static_dir.is_dir() {
        return Err(anyhow!(
            "{} has no .next/static — an SSR build needs both",
            build_dir.display()
        ));
    }

    let tmp = TempDir::new().context("create temp packaging directory")?;
    let pkg = tmp.path().join("pkg");

    // cp -r .next/standalone/. pkg/
    copy_tree(&standalone, &pkg).context("copy .next/standalone")?;

    // mkdir -p pkg/.next && cp -r .next/static pkg/.next/static
    copy_tree(&static_dir, &pkg.join(".next").join("static")).context("copy .next/static")?;

    // printf '#!/bin/bash\nexec node server.js\n' > pkg/run.sh; chmod +x pkg/run.sh
    let run_sh = pkg.join("run.sh");
    fs::write(&run_sh, RUN_SH).context("write run.sh")?;
    set_executable(&run_sh)?;

    // A single symlink in the zip breaks the Lambda bundle — hard fail.
    let links = find_symlinks(&pkg)?;
    if !links.is_empty() {
        let list = links
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n  ");
        return Err(anyhow!(
            "symlinks found in the packaged SSR bundle — the Lambda zip would break:\n  {list}"
        ));
    }

    let zip_path = tmp.path().join("ssr-bundle.zip");
    zip_dir(&pkg, &zip_path).context("zip SSR bundle")?;

    Ok((tmp, zip_path))
}

/// Recursively copy `src` into `dst` (created if absent), preserving
/// symlinks as symlinks — never dereferencing — so the post-copy symlink
/// guard in [`package_bundle`] stays meaningful, exactly like a plain
/// `cp -r` would behave.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("read directory {}", src.display()))? {
        let entry = entry.with_context(|| format!("read directory {}", src.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        let dest = dst.join(entry.file_name());
        if file_type.is_symlink() {
            copy_symlink(&entry.path(), &dest)?;
        } else if file_type.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &dest)
                .with_context(|| format!("copy {}", entry.path().display()))?;
            preserve_mode(&entry.path(), &dest)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dest: &Path) -> Result<()> {
    let target = fs::read_link(src).with_context(|| format!("read link {}", src.display()))?;
    std::os::unix::fs::symlink(&target, dest).with_context(|| {
        format!(
            "recreate symlink {} -> {}",
            dest.display(),
            target.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(src: &Path, _dest: &Path) -> Result<()> {
    Err(anyhow!(
        "symlink at {} — SSR bundle packaging needs a Unix host",
        src.display()
    ))
}

#[cfg(unix)]
fn preserve_mode(src: &Path, dest: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(src)
        .with_context(|| format!("stat {}", src.display()))?
        .permissions()
        .mode();
    fs::set_permissions(dest, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", dest.display()))
}

#[cfg(not(unix))]
fn preserve_mode(_src: &Path, _dest: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Result<u32> {
    Ok(0o644)
}

/// Recursively collect every symlink under `dir`.
fn find_symlinks(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    find_symlinks_into(dir, &mut out)?;
    Ok(out)
}

fn find_symlinks_into(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read directory {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        if file_type.is_symlink() {
            out.push(entry.path());
        } else if file_type.is_dir() {
            find_symlinks_into(&entry.path(), out)?;
        }
    }
    Ok(())
}

/// Zip the *contents* of `dir` (not `dir` itself) into `zip_path`, matching
/// `(cd pkg && zip -qry ../bundle.zip .)`: archive paths are relative to
/// `dir`, forward-slash, no leading `./`. Entries are visited in sorted
/// order for a reproducible archive.
fn zip_dir(dir: &Path, zip_path: &Path) -> Result<()> {
    let file = File::create(zip_path).with_context(|| format!("create {}", zip_path.display()))?;
    let mut zip = ZipWriter::new(file);
    add_dir_entries(&mut zip, dir, "")?;
    zip.finish().context("finalize zip")?;
    Ok(())
}

fn add_dir_entries(zip: &mut ZipWriter<File>, dir: &Path, prefix: &str) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("read directory {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("read directory {}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(anyhow!("non-UTF-8 name under {}", dir.display()));
        };
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        if file_type.is_dir() {
            zip.add_directory(format!("{rel}/"), SimpleFileOptions::default())?;
            add_dir_entries(zip, &entry.path(), &rel)?;
        } else if file_type.is_file() {
            let mode = file_mode(&entry.path())?;
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(mode);
            zip.start_file(rel, opts)?;
            let mut f = File::open(entry.path())
                .with_context(|| format!("open {}", entry.path().display()))?;
            std::io::copy(&mut f, zip)
                .with_context(|| format!("write {} into zip", entry.path().display()))?;
        }
        // Symlinks never reach here — `package_bundle` hard-fails on any
        // symlink found under `pkg` before this function is ever called.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn looks_like_standalone_detects_next_standalone() {
        let dir = TempDir::new().unwrap();
        assert!(!looks_like_standalone(dir.path()));
        write(dir.path(), ".next/standalone/server.js", "x");
        assert!(looks_like_standalone(dir.path()));
    }

    #[test]
    fn looks_like_standalone_false_for_plain_static_export() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "out/index.html", "hi");
        assert!(!looks_like_standalone(dir.path()));
    }

    #[test]
    fn package_bundle_errors_without_standalone() {
        let dir = TempDir::new().unwrap();
        let err = package_bundle(dir.path()).unwrap_err();
        assert!(err.to_string().contains(".next/standalone"), "{err}");
    }

    #[test]
    fn package_bundle_errors_without_static() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".next/standalone/server.js", "x");
        let err = package_bundle(dir.path()).unwrap_err();
        assert!(err.to_string().contains(".next/static"), "{err}");
    }

    #[test]
    fn package_bundle_produces_expected_zip_shape() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".next/standalone/server.js", "server");
        write(
            dir.path(),
            ".next/standalone/node_modules/pkg/index.js",
            "pkg",
        );
        write(dir.path(), ".next/static/chunks/app.js", "chunk");

        let (_tmp, zip_path) = package_bundle(dir.path()).expect("ok");
        assert!(zip_path.is_file());

        let file = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ".next/",
                ".next/static/",
                ".next/static/chunks/",
                ".next/static/chunks/app.js",
                "node_modules/",
                "node_modules/pkg/",
                "node_modules/pkg/index.js",
                "run.sh",
                "server.js",
            ]
        );

        let mut run_sh = archive.by_name("run.sh").unwrap();
        let mut contents = String::new();
        run_sh.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, RUN_SH);
    }

    #[cfg(unix)]
    #[test]
    fn package_bundle_hard_fails_on_symlink() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".next/standalone/server.js", "server");
        write(dir.path(), ".next/static/chunks/app.js", "chunk");
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join(".next/standalone/leaky-link"))
            .unwrap();

        let err = package_bundle(dir.path()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn run_sh_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        write(dir.path(), ".next/standalone/server.js", "server");
        write(dir.path(), ".next/static/chunks/app.js", "chunk");

        let (tmp, _zip_path) = package_bundle(dir.path()).expect("ok");
        let run_sh = tmp.path().join("pkg").join("run.sh");
        let mode = fs::metadata(&run_sh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}
