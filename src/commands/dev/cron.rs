//! A minimal UTC cron engine for the dev runner.
//!
//! 🔴 WHY THIS EXISTS. `mirrorstack dev --tunnel` invokes NO crons. A module can
//! declare `ms.Cron("dispatch-outbox", "* * * * *", …)` and it will never run
//! once in dev: nothing logs, nothing errors, the queue simply grows. Measured
//! on twkpa-edu — 21 rows in a lifecycle outbox at `attempts = 0`, never
//! attempted, across a month.
//!
//! It falls between two drivers. The EventBridge driver excludes dev-mount
//! installs by design (`cron_decls.go` returns early on a NULL version), and
//! dispatch's in-process ticker only runs in its non-Lambda branch. Production
//! is correctly wired; a tunnel-connected module against production dispatch
//! has no driver at all.
//!
//! Two consequences, and only one is visible. Loud: user-core QUEUES
//! `user.created` rather than emitting it inline, so it never reaches
//! users-roles and a new registration gets NO default role even though the role
//! is `is_default = t`. Silent: the METER outbox stalls the same way, so the
//! billing panel under-reports — which reads as low usage, not as undelivered
//! telemetry.
//!
//! Deliberately NOT a general cron implementation: five fields, UTC only, no
//! seconds, no names, no `@hourly`. That is the whole surface `ms.Cron` accepts
//! today, and a matcher that claims more than it supports is worse than one
//! that refuses what it does not understand.

use anyhow::{Result, anyhow};

/// One parsed field of a cron expression, as the set of values it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    allowed: Vec<u32>,
}

impl Field {
    fn parse(spec: &str, min: u32, max: u32, label: &str) -> Result<Self> {
        let mut allowed = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(anyhow!("{label} has an empty item in {spec:?}"));
            }
            let (range, step) = match part.split_once('/') {
                Some((range, step)) => {
                    let step: u32 = step
                        .parse()
                        .map_err(|_| anyhow!("{label} has a non-numeric step in {part:?}"))?;
                    if step == 0 {
                        return Err(anyhow!("{label} has a zero step in {part:?}"));
                    }
                    (range, step)
                }
                None => (part, 1),
            };
            let (start, end) = if range == "*" {
                (min, max)
            } else if let Some((from, to)) = range.split_once('-') {
                (
                    parse_value(from, min, max, label)?,
                    parse_value(to, min, max, label)?,
                )
            } else {
                let value = parse_value(range, min, max, label)?;
                // A bare value with a step counts UP from it, which is what
                // "5/15" means everywhere else cron is spoken.
                if step > 1 {
                    (value, max)
                } else {
                    (value, value)
                }
            };
            if start > end {
                return Err(anyhow!("{label} range is inverted in {part:?}"));
            }
            let mut value = start;
            while value <= end {
                allowed.push(value);
                value += step;
            }
        }
        allowed.sort_unstable();
        allowed.dedup();
        if allowed.is_empty() {
            return Err(anyhow!("{label} matches nothing in {spec:?}"));
        }
        Ok(Self { allowed })
    }

    fn matches(&self, value: u32) -> bool {
        self.allowed.binary_search(&value).is_ok()
    }
}

fn parse_value(text: &str, min: u32, max: u32, label: &str) -> Result<u32> {
    let value: u32 = text
        .trim()
        .parse()
        .map_err(|_| anyhow!("{label} is not a number: {text:?}"))?;
    if value < min || value > max {
        return Err(anyhow!("{label} is out of range {min}-{max}: {value}"));
    }
    Ok(value)
}

/// A five-field UTC cron expression: minute hour day-of-month month day-of-week.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Schedule {
    minute: Field,
    hour: Field,
    day_of_month: Field,
    month: Field,
    day_of_week: Field,
    /// True when BOTH day fields are restricted. Cron's oldest wart: with both
    /// set they are OR'd, not AND'd, so "0 0 1 * 1" fires on the 1st AND on
    /// every Monday. Getting this wrong makes a job fire far more often than
    /// its author intended, which is the direction that hurts.
    day_union: bool,
}

impl Schedule {
    pub(crate) fn parse(expression: &str) -> Result<Self> {
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(anyhow!(
                "expected 5 cron fields (minute hour day month weekday), got {}: {expression:?}",
                fields.len()
            ));
        }
        Ok(Self {
            minute: Field::parse(fields[0], 0, 59, "minute")?,
            hour: Field::parse(fields[1], 0, 23, "hour")?,
            day_of_month: Field::parse(fields[2], 1, 31, "day of month")?,
            month: Field::parse(fields[3], 1, 12, "month")?,
            // 0 and 7 both mean Sunday, as everywhere else.
            day_of_week: Field::parse(&fields[4].replace('7', "0"), 0, 6, "day of week")?,
            day_union: fields[2] != "*" && fields[4] != "*",
        })
    }

    /// Report whether this schedule fires during the UTC minute containing
    /// `unix_seconds`.
    pub(crate) fn matches_minute(&self, unix_seconds: i64) -> bool {
        let time = UtcTime::from_unix(unix_seconds);
        if !self.minute.matches(time.minute) || !self.hour.matches(time.hour) {
            return false;
        }
        if !self.month.matches(time.month) {
            return false;
        }
        let dom = self.day_of_month.matches(time.day);
        let dow = self.day_of_week.matches(time.weekday);
        if self.day_union {
            dom || dow
        } else {
            dom && dow
        }
    }
}

/// The civil UTC fields of a unix timestamp.
#[derive(Debug, PartialEq, Eq)]
struct UtcTime {
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    weekday: u32,
}

impl UtcTime {
    /// Convert without a date library, using Howard Hinnant's civil_from_days.
    /// UTC only, so there is no DST case to get wrong — which is also why the
    /// dev ticker is defined in UTC rather than local time.
    fn from_unix(unix_seconds: i64) -> Self {
        let days = unix_seconds.div_euclid(86_400);
        let seconds_of_day = unix_seconds.rem_euclid(86_400);

        // 1970-01-01 was a Thursday (weekday 4 with Sunday = 0).
        let weekday = (days + 4).rem_euclid(7) as u32;

        // The year is deliberately not reconstructed: it would be
        // `yoe + era * 400 + (month <= 2)`, and a five-field cron has no year
        // field, so the era term and the year itself are dead weight.
        let z = days + 719_468;
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;

        Self {
            minute: (seconds_of_day / 60 % 60) as u32,
            hour: (seconds_of_day / 3_600) as u32,
            day,
            month,
            weekday,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-07T00:00:00Z — exactly a UTC midnight, so a "+ n * 60" walk
    /// lands on clean minute boundaries.
    const MIDNIGHT: i64 = 1_788_739_200;

    /// Known-good UTC instants, so the hand-rolled civil-date conversion is
    /// checked against dates rather than against itself.
    #[test]
    fn utc_time_matches_known_instants() {
        // 1970-01-01T00:00:00Z — a Thursday.
        let epoch = UtcTime::from_unix(0);
        assert_eq!(
            (
                epoch.minute,
                epoch.hour,
                epoch.day,
                epoch.month,
                epoch.weekday
            ),
            (0, 0, 1, 1, 4)
        );

        // 2026-09-07T12:05:00Z — a Monday.
        let t = UtcTime::from_unix(1_788_782_700);
        assert_eq!(
            (t.minute, t.hour, t.day, t.month, t.weekday),
            (5, 12, 7, 9, 1)
        );

        // 2024-02-29T23:59:00Z — a leap day, Thursday.
        let leap = UtcTime::from_unix(1_709_251_140);
        assert_eq!(
            (leap.minute, leap.hour, leap.day, leap.month, leap.weekday),
            (59, 23, 29, 2, 4)
        );

        // 2000-03-01T00:00:00Z — the century-leap-year boundary, Wednesday.
        let century = UtcTime::from_unix(951_868_800);
        assert_eq!((century.day, century.month, century.weekday), (1, 3, 3));
    }

    #[test]
    fn every_minute_matches_every_minute() {
        let every = Schedule::parse("* * * * *").expect("parse");
        for offset in [0, 60, 3_600, 86_400, 1_788_782_700] {
            assert!(every.matches_minute(offset), "missed {offset}");
        }
    }

    #[test]
    fn a_daily_job_fires_once_a_day() {
        // 03:00 UTC daily. Rather than trust a memorised timestamp, walk a
        // whole day a minute at a time and require exactly one match — a
        // property that cannot pass by luck of picking the right instant.
        let daily = Schedule::parse("0 3 * * *").expect("parse");
        let hits = (0..1_440)
            .filter(|m| daily.matches_minute(MIDNIGHT + m * 60))
            .count();
        assert_eq!(hits, 1, "a daily job must fire once per day");
    }

    #[test]
    fn steps_and_lists_and_ranges() {
        let quarter = Schedule::parse("*/15 * * * *").expect("parse");
        let hits = (0..60)
            .filter(|m| quarter.matches_minute(MIDNIGHT + m * 60))
            .count();
        assert_eq!(hits, 4);

        let listed = Schedule::parse("0,30 * * * *").expect("parse");
        assert_eq!(
            (0..60)
                .filter(|m| listed.matches_minute(MIDNIGHT + m * 60))
                .count(),
            2
        );

        let ranged = Schedule::parse("0-4 * * * *").expect("parse");
        assert_eq!(
            (0..60)
                .filter(|m| ranged.matches_minute(MIDNIGHT + m * 60))
                .count(),
            5
        );
    }

    /// 🔴 Cron's oldest wart: with BOTH day fields restricted they are OR'd,
    /// not AND'd. Getting it wrong makes a job fire far more often than its
    /// author intended, which is the direction that hurts.
    #[test]
    fn both_day_fields_restricted_means_union() {
        let union = Schedule::parse("0 0 1 * 1").expect("parse");
        // Count matches across 60 days: far more than one, because every Monday
        // counts as well as every 1st.
        let hits = (0..60)
            .filter(|d| union.matches_minute(MIDNIGHT + d * 86_400))
            .count();
        assert!(
            hits > 5,
            "union of day fields should fire on Mondays too, got {hits}"
        );

        // With only day-of-month set, it is a strict monthly job.
        let monthly = Schedule::parse("0 0 1 * *").expect("parse");
        let monthly_hits = (0..60)
            .filter(|d| monthly.matches_minute(MIDNIGHT + d * 86_400))
            .count();
        assert!(
            monthly_hits <= 2,
            "monthly job fired {monthly_hits} times in 60 days"
        );
    }

    #[test]
    fn sunday_is_both_zero_and_seven() {
        let zero = Schedule::parse("0 0 * * 0").expect("parse");
        let seven = Schedule::parse("0 0 * * 7").expect("parse");
        for d in 0..14 {
            let t = MIDNIGHT + d * 86_400;
            assert_eq!(zero.matches_minute(t), seven.matches_minute(t), "day {d}");
        }
    }

    /// Refuse what it does not understand rather than silently matching
    /// nothing — a cron that never fires and never complains is the failure
    /// this whole module exists to remove.
    #[test]
    fn malformed_expressions_are_refused() {
        for bad in [
            "",
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * 32 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "abc * * * *",
            "* * * * a",
            "1,, * * * *",
        ] {
            assert!(Schedule::parse(bad).is_err(), "accepted {bad:?}");
        }
    }
    /// The supervisor loop spins far faster than a minute, so the guard that
    /// makes a job fire ONCE per minute is what stops a "* * * * *" cron from
    /// being hammered continuously — which for an outbox drain would mean
    /// concurrent drains of the same rows.
    #[test]
    fn a_job_fires_at_most_once_per_minute() {
        // Port 1 is unreachable, so load_jobs fails and no HTTP is attempted;
        // what is under test is the minute guard, not the request.
        let mut ticker = Ticker::new("app-1".into(), "user-core".into(), 1, None);

        // 2026-09-07T12:05:00Z, already on a minute boundary.
        let minute_start = 1_788_782_700;
        assert!(ticker.tick(minute_start).is_empty());
        // Same minute, later second: the guard short-circuits before any work.
        assert_eq!(ticker.last_minute, Some(minute_start / 60));
        assert!(ticker.tick(minute_start + 59).is_empty());
        assert_eq!(ticker.last_minute, Some(minute_start / 60));

        // Next minute advances the guard.
        assert!(ticker.tick(minute_start + 60).is_empty());
        assert_eq!(ticker.last_minute, Some(minute_start / 60 + 1));
    }
}

/// One parsed cron job: what to call, and when.
#[derive(Debug, Clone)]
struct Job {
    name: String,
    path: String,
    schedule: Schedule,
}

/// Fires a module's declared crons locally, once per UTC minute.
///
/// Deliberately per-module and in the module's own supervisor loop: no new
/// thread, no cross-module coordination, and it stops when the module does.
pub(crate) struct Ticker {
    app_id: String,
    slug: String,
    base_url: String,
    platform_token: Option<String>,
    /// Parsed (schedule, path) pairs, loaded on the first tick and refreshed
    /// whenever the manifest read succeeds again after a failure.
    jobs: Option<Vec<Job>>,
    /// The last UTC minute already fired, so a loop that spins faster than a
    /// minute cannot fire the same job twice.
    last_minute: Option<i64>,
    client: reqwest::blocking::Client,
}

impl Ticker {
    pub(crate) fn new(
        app_id: String,
        slug: String,
        port: u16,
        platform_token: Option<String>,
    ) -> Self {
        Self {
            app_id,
            slug,
            base_url: format!("http://127.0.0.1:{port}"),
            platform_token,
            jobs: None,
            last_minute: None,
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fire whatever is due for the UTC minute containing `now_unix`.
    ///
    /// Returns the names fired, for the caller to log. Every failure is
    /// reported and none is fatal: a cron that cannot run must not take the
    /// developer's module down with it.
    pub(crate) fn tick(&mut self, now_unix: i64) -> Vec<(String, Result<()>)> {
        let minute = now_unix.div_euclid(60);
        if self.last_minute == Some(minute) {
            return Vec::new();
        }
        self.last_minute = Some(minute);

        if self.jobs.is_none() {
            self.jobs = self.load_jobs();
        }
        let Some(jobs) = self.jobs.as_ref() else {
            return Vec::new();
        };

        let due: Vec<Job> = jobs
            .iter()
            .filter(|job| job.schedule.matches_minute(now_unix))
            .cloned()
            .collect();

        due.into_iter()
            .map(|job| {
                let outcome = self.fire(&job.path);
                (job.name, outcome)
            })
            .collect()
    }

    /// Read the module's manifest and parse every schedule it declares.
    ///
    /// A schedule this engine cannot parse is REPORTED and skipped rather than
    /// silently dropped — an unparsed cron that never fires is the exact
    /// failure this whole module exists to remove.
    fn load_jobs(&self) -> Option<Vec<Job>> {
        let url = format!("{}/__mirrorstack/platform/manifest", self.base_url);
        let response = self.request(self.client.get(url)).send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let manifest: crate::commands::module::capabilities::wire::Manifest =
            response.json().ok()?;
        let mut jobs = Vec::new();
        for schedule in &manifest.schedules {
            match Schedule::parse(&schedule.cron) {
                Ok(parsed) => jobs.push(Job {
                    name: schedule.name.clone(),
                    path: schedule.path.clone(),
                    schedule: parsed,
                }),
                Err(error) => eprintln!(
                    "  cron {}/{}: unsupported schedule {:?} — {error}",
                    self.slug, schedule.name, schedule.cron
                ),
            }
        }
        Some(jobs)
    }

    fn fire(&self, path: &str) -> Result<()> {
        let url = format!("{}{path}", self.base_url);
        let response = self
            .request(self.client.post(url))
            .header("content-length", "0")
            .send()?;
        if !response.status().is_success() {
            return Err(anyhow!("HTTP {}", response.status().as_u16()));
        }
        Ok(())
    }

    /// 🔴 Both headers are required, and each was a wrong turn when missing.
    /// `MS_PLATFORM_TOKEN_FILE` outranks `MS_INTERNAL_SECRET` in the SDK's
    /// reader, so the expected header is `X-MS-Platform-Token` — a module logs
    /// `header_present=false` while a different header IS being sent. And the
    /// cron is APP-SCOPED: without `X-MS-App-ID` it fails with "outbox dispatch
    /// requires trusted app context".
    fn request(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        let builder = builder.header("X-MS-App-ID", &self.app_id);
        match &self.platform_token {
            Some(token) => builder.header("X-MS-Platform-Token", token),
            None => builder,
        }
    }
}
