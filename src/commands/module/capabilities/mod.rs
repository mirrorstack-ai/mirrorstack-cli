use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::Args;
use console::style;

use crate::commands::{ok_mark, warn_prefix};

pub(crate) mod index;
pub(crate) mod resolve;
mod schema;
mod version;
pub(crate) mod wire;

use index::{Report, Severity};

#[derive(Args)]
pub struct CapabilitiesArgs {
    /// Workspace directory containing go.work. Defaults to the nearest go.work at or above the cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Resolve against module versions installed in this app (id or slug).
    #[arg(long)]
    app: Option<String>,
    /// Only report this host module's slots and contributors.
    #[arg(long)]
    host: Option<String>,
    /// Machine-readable output on stdout.
    #[arg(long)]
    json: bool,
}

fn workspace_root(dir: Option<&Path>) -> Result<PathBuf> {
    let start = dir
        .map(Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    start
        .ancestors()
        .find(|p| p.join("go.work").exists())
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("no go.work found at or above {}", start.display()))
}

pub(crate) fn run(args: CapabilitiesArgs) -> Result<()> {
    // Tier P marketplace resolution is deliberately out of scope: this command
    // reports only live co-location or versions actually installed in an app.
    let (resolved, unreachable, source) = if let Some(app) = &args.app {
        let (r, u) = resolve::tier_app(app)?;
        (r, u, format!("tier D · versions installed in {app}"))
    } else {
        let root = workspace_root(args.dir.as_deref())?;
        let (r, u) = resolve::tier_local(&root)?;
        if r.is_empty() {
            // Tier L reads LIVE manifests, the same source the runtime
            // authorizes against — validating against local Go source instead
            // would be theatre. So with nothing running there is no answer.
            for module in &u {
                eprintln!("{} {}: {}", warn_prefix(), module.slug, module.reason);
            }
            return Err(anyhow!(
                "no module manifest could be read — run `mirrorstack dev --tunnel` in this workspace so co-located modules serve their manifests"
            ));
        }
        (
            r,
            u,
            format!("tier L · co-located go.work modules at {}", root.display()),
        )
    };
    let mut report = index::classify(&resolved);
    report
        .diagnostics
        .extend(resolve::unreachable_diagnostics(&unreachable));
    index::sort_report(&mut report);
    if let Some(host) = &args.host {
        report = index::filter_host(report, host);
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&source, &report);
    }
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    if errors > 0 {
        return Err(anyhow!(
            "{errors} capability error(s) — see the diagnostics above"
        ));
    }
    Ok(())
}

/// Every line is tagged with the tier and version it came from — the module
/// header carries them for its own declarations, and each slot line repeats
/// them because slots from different hosts (and tiers) interleave. An
/// untagged capability answer is a bug.
fn print_human(source: &str, report: &Report) {
    eprintln!("{} {}", ok_mark(), style(source).bold());
    for module in &report.resolved {
        eprintln!(
            "\n  {}@{} {}",
            style(&module.module).cyan().bold(),
            module.version,
            style(format!("[tier {}]", module.tier)).dim()
        );
        let keys: Vec<_> = module.provides.iter().map(|s| s.key.as_str()).collect();
        for (label, values) in [
            ("provides", keys.join(", ")),
            ("exposes", module.exposes.tables.join(", ")),
            ("permissions", module.permissions.join(", ")),
            ("emits", module.events.emits.join(", ")),
        ] {
            if !values.is_empty() {
                eprintln!("    {:<12}{values}", style(label).dim());
            }
        }
    }

    eprintln!("\n{}", style("Slots").bold());
    for slot in &report.slots {
        let where_from = style(format!("[{} tier {}]", slot.host_version, slot.tier)).dim();
        if slot.filled_by.is_empty() {
            eprintln!(
                "  {} {}/{} {where_from} {}",
                style("○").yellow(),
                slot.host,
                style(&slot.key).yellow(),
                style("unfilled").yellow()
            );
        } else {
            let filled = slot
                .filled_by
                .iter()
                .map(|f| format!("{}@{} [tier {}]", f.module, f.version, f.tier))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "  {} {}/{} {where_from} filled by {filled}",
                ok_mark(),
                slot.host,
                slot.key
            );
        }
    }

    if !report.diagnostics.is_empty() {
        eprintln!("\n{}", style("Diagnostics").bold());
        for d in &report.diagnostics {
            let prefix = match d.severity {
                Severity::Error => style("error:").red().bold(),
                Severity::Warning => style("warning:").yellow().bold(),
                Severity::Info => style("info: ").dim().bold(),
            };
            eprintln!(
                "  {prefix} {} {} {}",
                style(&d.code).bold(),
                style(&d.module).cyan(),
                d.detail
            );
        }
    }

    let unfilled = report
        .slots
        .iter()
        .filter(|s| s.filled_by.is_empty())
        .count();
    let errors = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    eprintln!(
        "\n{} slots · {} unfilled · {} error{}",
        report.slots.len(),
        unfilled,
        errors,
        if errors == 1 { "" } else { "s" }
    );
}
