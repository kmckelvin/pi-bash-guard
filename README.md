# pi-bash-guard extension

`pi-bash-guard` prevents Pi from using certain bash commands. It makes it safer to work on repositories that contain scripts or automation which might invoke Kubernetes or Google Cloud CLIs.

While it was initially created to guard `kubectl` and `gcloud`, you can block or permit arbitrary **command prefixes**.

By default, a fresh install blocks:

- `gcloud`
- `kubectl`

## What it protects

The guard applies to both:

- agent `bash` tool calls
- user `!` commands

## Prefix-based behavior

Matching is prefix-based.

Example:

- If `kubectl` is blocked
- and you run `/bash-guard-permit kubectl -n staging`

then `kubectl -n staging ...` is allowed, while other `kubectl ...` invocations remain blocked.

## Persistence

Config is stored at:

- `~/.pi/agent/extensions/bash-guard.json`

Persistent rules survive restarts.
Session rules are cleared on session start (or via `/bash-guard-reset`).

## Commands

- `/bash-guard-block <prefix>`
  - block prefix for the current session
- `/bash-guard-permit <prefix>`
  - permit prefix for the current session
- `/bash-guard-block-persist <prefix>`
  - persistently block prefix between sessions
  - if that prefix was persistently permitted and is already covered by another persistent block prefix, it is deduplicated by removing the permit without adding a redundant block rule
- `/bash-guard-permit-persist <prefix>`
  - persistently permit prefix between sessions
- `/bash-guard-reset`
  - clear all session-only guard values (both session blocks and session permits)
- `/bash-guard-status`
  - show persistent + session rules and matching precedence

## Rule precedence

Resolution order is:

1. Session rules
2. Persistent rules

Within each layer, more specific prefix wins. If two rules are equally specific, permit wins.

## Examples

```text
/bash-guard-block-persist kubectl
/bash-guard-permit kubectl -n staging
/bash-guard-block kubectl -n alpha
/bash-guard-status
/bash-guard-reset
```

## Install

### Project-local

```bash
mkdir -p .pi/extensions/pi-bash-guard
cp ~/code/pi-ext/pi-bash-guard/index.ts .pi/extensions/pi-bash-guard/index.ts
```

### Global

```bash
mkdir -p ~/.pi/agent/extensions/pi-bash-guard
cp ~/code/pi-ext/pi-bash-guard/index.ts ~/.pi/agent/extensions/pi-bash-guard/index.ts
```

Then reload Pi:

```text
/reload
```
