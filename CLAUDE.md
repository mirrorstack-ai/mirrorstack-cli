# Claude guidance

## Core manifest pointer automation

After a PR merges to protected `main`, a successful terminal `CI` run triggers
`.github/workflows/notify-core-pointer.yml`. The workflow sends the exact
`mirrorstack-cli` main SHA to `mirrorstack-ai/mirrorstack-core-v2`, where
`mirrorstack-core-bot` opens or updates the commit-bound pointer PR.

Claude must not manually edit or push the core gitlink during the normal flow.
The automation only opens/updates a reviewable PR; it never reviews, merges,
promotes, or deploys. If the PR is missing, inspect the terminal CI/CD run and
`Notify core pointer` run first; core's scheduled scan remains the fallback.
