//! Linux URL-scheme registration through a per-user desktop entry.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::process::Command;

use super::register::RegistrationOutcome;

const DESKTOP_FILE: &str = "mirrorstack-url.desktop";
const MIME_TYPE: &str = "x-scheme-handler/mirrorstack";

/// Install and select the per-user desktop handler for `mirrorstack://` URLs.
pub fn register() -> RegistrationOutcome {
    match register_inner() {
        Ok(()) => RegistrationOutcome::Registered,
        Err(error) => RegistrationOutcome::Failed(error),
    }
}

fn register_inner() -> Result<(), String> {
    let exe = env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?;
    let exe = fs::canonicalize(&exe)
        .map_err(|error| format!("canonicalize executable {}: {error}", exe.display()))?;
    let exe = exe
        .to_str()
        .ok_or_else(|| "current executable path is not valid UTF-8".to_owned())?;

    let data_dir =
        dirs::data_local_dir().ok_or_else(|| "locate the per-user data directory".to_owned())?;
    let applications_dir = data_dir.join("applications");
    fs::create_dir_all(&applications_dir).map_err(|error| {
        format!(
            "create applications directory {}: {error}",
            applications_dir.display()
        )
    })?;

    let desktop_path = applications_dir.join(DESKTOP_FILE);
    let desktop = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=MirrorStack CLI URL Handler\n\
         Exec={} __oauth-deliver %u\n\
         MimeType={MIME_TYPE};\n\
         NoDisplay=true\n",
        quote_exec(exe)
    );
    fs::write(&desktop_path, desktop)
        .map_err(|error| format!("write desktop entry {}: {error}", desktop_path.display()))?;

    // This utility is optional and some minimal desktop installations omit it.
    let _ = run("update-desktop-database", [applications_dir.as_os_str()]);

    run(
        "xdg-mime",
        [
            OsStr::new("default"),
            OsStr::new(DESKTOP_FILE),
            OsStr::new(MIME_TYPE),
        ],
    )
    .map_err(|error| format!("xdg-mime: {error}"))?;

    Ok(())
}

fn quote_exec(exe: &str) -> String {
    let mut escaped = String::with_capacity(exe.len());
    for character in exe.chars() {
        if matches!(character, '\\' | '"' | '`' | '$') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    format!("\"{escaped}\"")
}

fn run<I, S>(command: &str, args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }

    Err(command_error(command, output.status, &output.stderr))
}

fn command_error(command: &str, status: std::process::ExitStatus, stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        format!("{command} exited with {status}")
    } else {
        stderr.to_owned()
    }
}
