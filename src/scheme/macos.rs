//! macOS URL-scheme registration through a locally generated applet bundle.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use super::register::RegistrationOutcome;

const APP_NAME: &str = "MirrorStackURL.app";
const PLIST_BUDDY: &str = "/usr/libexec/PlistBuddy";
const LS_REGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister";

/// Generate and register the per-user applet handling `mirrorstack://` URLs.
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

    let applications_dir = dirs::home_dir()
        .ok_or_else(|| "locate the home directory".to_owned())?
        .join("Applications");
    fs::create_dir_all(&applications_dir).map_err(|error| {
        format!(
            "create applications directory {}: {error}",
            applications_dir.display()
        )
    })?;
    let bundle = applications_dir.join(APP_NAME);

    let source = format!(
        "on open location this_URL\n\
         \x20   do shell script quoted form of \"{}\" & \" __oauth-deliver \" & quoted form of this_URL\n\
         end open location\n",
        escape_applescript_string(exe)
    );
    let mut script = tempfile::Builder::new()
        .prefix("mirrorstack-url-")
        .suffix(".applescript")
        .tempfile()
        .map_err(|error| format!("create temporary AppleScript: {error}"))?;
    script
        .write_all(source.as_bytes())
        .map_err(|error| format!("write temporary AppleScript: {error}"))?;
    script
        .flush()
        .map_err(|error| format!("flush temporary AppleScript: {error}"))?;

    run(
        "osacompile",
        [
            OsStr::new("-o"),
            bundle.as_os_str(),
            script.path().as_os_str(),
        ],
    )
    .map_err(|error| format!("osacompile: {error}"))?;

    let plist = bundle.join("Contents").join("Info.plist");
    write_scheme_plist(&plist)?;

    run(
        "codesign",
        [
            OsStr::new("-s"),
            OsStr::new("-"),
            OsStr::new("--force"),
            bundle.as_os_str(),
        ],
    )
    .map_err(|error| format!("codesign: {error}"))?;
    run(LS_REGISTER, [OsStr::new("-f"), bundle.as_os_str()])
        .map_err(|error| format!("Launch Services registration: {error}"))?;

    if !bundle.is_dir() {
        return Err(format!(
            "app bundle was not created at {}",
            bundle.display()
        ));
    }
    if !plist.is_file() {
        return Err(format!(
            "URL-scheme metadata was not written to {}",
            plist.display()
        ));
    }

    Ok(())
}

fn write_scheme_plist(plist: &Path) -> Result<(), String> {
    // The applet is ours, so replacing this one key is safe and makes reruns
    // deterministic. A missing key is the expected first-run delete failure.
    let _ = plist_buddy("Delete :CFBundleURLTypes", plist);
    plist_buddy("Add :CFBundleURLTypes array", plist)?;
    plist_buddy("Add :CFBundleURLTypes:0 dict", plist)?;
    plist_buddy(
        "Add :CFBundleURLTypes:0:CFBundleURLName string ai.mirrorstack.cli.url",
        plist,
    )?;
    plist_buddy("Add :CFBundleURLTypes:0:CFBundleURLSchemes array", plist)?;
    plist_buddy(
        "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string mirrorstack",
        plist,
    )?;
    Ok(())
}

fn plist_buddy(instruction: &str, plist: &Path) -> Result<(), String> {
    run(
        PLIST_BUDDY,
        [OsStr::new("-c"), OsStr::new(instruction), plist.as_os_str()],
    )
    .map_err(|error| format!("PlistBuddy `{instruction}`: {error}"))
}

fn escape_applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        Err(format!("{command} exited with {}", output.status))
    } else {
        Err(stderr.to_owned())
    }
}
