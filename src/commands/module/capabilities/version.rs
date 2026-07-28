use crate::commands::dev::module_meta::{SemVer, parse_semver, semver_from_core};

#[derive(Clone, Copy)]
enum Op {
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

fn parse_partial(raw: &str) -> Option<(u64, u64, u64, usize, bool)> {
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let parts: Vec<_> = raw.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut nums = [0; 3];
    let mut wildcard = false;
    for (i, part) in parts.iter().enumerate() {
        if *part == "x" || *part == "X" || *part == "*" {
            wildcard = true;
            return Some((nums[0], nums[1], nums[2], i, wildcard));
        }
        nums[i] = part.parse().ok()?;
    }
    Some((nums[0], nums[1], nums[2], parts.len(), wildcard))
}

fn compare(version: &SemVer, op: Op, bound: &SemVer) -> bool {
    match op {
        Op::Eq => version == bound,
        Op::Gt => version > bound,
        Op::Ge => version >= bound,
        Op::Lt => version < bound,
        Op::Le => version <= bound,
    }
}

fn range(version: &SemVer, lo: SemVer, hi: SemVer) -> bool {
    version >= &lo && version < &hi
}

fn matches_token(token: &str, version: &SemVer) -> bool {
    let (op, operand) = [
        (">=", Op::Ge),
        ("<=", Op::Le),
        ("==", Op::Eq),
        (">", Op::Gt),
        ("<", Op::Lt),
        ("=", Op::Eq),
    ]
    .into_iter()
    .find_map(|(prefix, op)| token.strip_prefix(prefix).map(|v| (Some(op), v)))
    .unwrap_or((None, token));
    if let Some(rest) = operand.strip_prefix('^') {
        let Some((a, b, c, _, _)) = parse_partial(rest) else {
            return true;
        };
        let hi = if a > 0 {
            semver_from_core(a + 1, 0, 0)
        } else if b > 0 {
            semver_from_core(0, b + 1, 0)
        } else {
            semver_from_core(0, 0, c + 1)
        };
        return range(version, semver_from_core(a, b, c), hi);
    }
    if let Some(rest) = operand.strip_prefix('~') {
        let Some((a, b, c, count, _)) = parse_partial(rest) else {
            return true;
        };
        let hi = if count == 1 {
            semver_from_core(a + 1, 0, 0)
        } else {
            semver_from_core(a, b + 1, 0)
        };
        return range(version, semver_from_core(a, b, c), hi);
    }
    let operand = operand.strip_prefix('v').unwrap_or(operand);
    // A fully-qualified operand — including a prerelease like `0.1.0-dev`, which
    // the partial parser cannot express — compares directly. Without this branch
    // an exact prerelease pin would fall through to `parse_partial`, fail on the
    // `-dev` segment, and never match even its own version.
    if let Some(bound) = parse_semver(operand) {
        return compare(version, op.unwrap_or(Op::Eq), &bound);
    }
    // An unrecognized token is lenient: a constraint we cannot read must not
    // manufacture a version_skew error.
    let Some((a, b, c, count, wildcard)) = parse_partial(operand) else {
        return true;
    };
    if let Some(op) = op {
        return compare(version, op, &semver_from_core(a, b, c));
    }
    // A bare wildcard (`x`, `*`) constrains nothing.
    if wildcard && count == 0 {
        return true;
    }
    if wildcard || count < 3 {
        let hi = if count == 1 {
            semver_from_core(a + 1, 0, 0)
        } else {
            semver_from_core(a, b + 1, 0)
        };
        return range(version, semver_from_core(a, b, 0), hi);
    }
    compare(version, Op::Eq, &semver_from_core(a, b, c))
}

/// Does `version` satisfy an npm-style constraint?
pub(crate) fn satisfies(constraint: &str, version: &str) -> bool {
    let Some(version) = parse_semver(version.strip_prefix('v').unwrap_or(version)) else {
        return true;
    };
    let constraint = constraint.trim();
    if constraint.is_empty() || matches!(constraint, "*" | "x" | "X") {
        return true;
    }
    constraint.split("||").any(|alternative| {
        alternative
            .replace(',', " ")
            .split_whitespace()
            .all(|token| matches_token(token, &version))
    })
}

#[cfg(test)]
mod tests {
    use super::satisfies;

    #[test]
    fn operators_ranges_wildcards_and_or() {
        assert!(satisfies(">=1.2.0 <2", "1.5.0"));
        assert!(satisfies(">1.2 <=1.3.0", "1.3.0"));
        assert!(!satisfies("<1.2.3", "1.2.3"));
        assert!(satisfies("=1.2.3", "v1.2.3"));
        assert!(satisfies("==v1.2.3", "1.2.3"));
        assert!(satisfies("1", "1.9.0"));
        assert!(satisfies("1.2", "1.2.8"));
        assert!(satisfies("1.x", "1.8.0"));
        assert!(satisfies("1.*", "1.8.0"));
        assert!(satisfies("1.2.x", "1.2.9"));
        assert!(satisfies("2 || ^1.2", "1.4.0"));
    }

    #[test]
    fn caret_and_tilde_ranges() {
        assert!(satisfies("^0.1", "0.1.9"));
        assert!(!satisfies("^0.1", "0.2.0"));
        assert!(satisfies("^0.0.3", "0.0.3"));
        assert!(!satisfies("^0.0.3", "0.0.4"));
        assert!(satisfies("^1.2", "1.9.0"));
        assert!(!satisfies("^1.2", "2.0.0"));
        assert!(satisfies("~1.2.3", "1.2.9"));
        assert!(!satisfies("~1.2.3", "1.3.0"));
        assert!(satisfies("~1.2", "1.2.9"));
        assert!(satisfies("~1", "1.9.0"));
    }

    #[test]
    fn prereleases_rank_below_their_release() {
        assert!(!satisfies(">=1.0.0", "1.0.0-beta"));
        // An exact prerelease pin must match itself — the partial parser cannot
        // express `-dev`, so this exercises the full-SemVer branch.
        assert!(satisfies("0.1.0-dev", "0.1.0-dev"));
        assert!(!satisfies("0.1.0-dev", "0.1.0"));
        assert!(satisfies(">=0.1.0-dev", "0.1.0"));
    }

    #[test]
    fn unreadable_input_never_manufactures_a_mismatch() {
        assert!(satisfies("^1", "not-semver"));
        assert!(satisfies("whatever-this-is", "1.2.3"));
        assert!(satisfies("", "1.2.3"));
        assert!(satisfies("*", "1.2.3"));
        assert!(satisfies("x", "1.2.3"));
        assert!(satisfies(">=1.0.0 || x", "0.1.0"));
    }
}
