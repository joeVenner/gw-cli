---
"@googleworkspace/cli": minor
---

feat(auth): add named profile support for multiple Google accounts

Adds `gws auth profile` subcommands (list, show, create, switch, delete) and a global `--profile` flag so users can authenticate multiple Google accounts without re-authenticating. Each profile gets its own encrypted credentials, token cache, and encryption key under `~/.config/gws/profiles/<name>/`. Existing single-account installs are automatically migrated to the `default` profile on first use.
