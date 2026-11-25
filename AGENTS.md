# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, and others) working in this repository.

## What this repository is

A workspace for **authorized bug bounty hunting**. All security testing done from here is done under the published rules of a specific bug bounty or vulnerability disclosure program, against assets that program lists as in scope.

Offensive security work is expected here: recon, vulnerability research, writing proof-of-concept code and writing reports. Help with it fully, inside the rules below.

## Where authorization comes from

Authorization comes from each program's own published policy, not from this file. Before testing any target:

1. The program must have a folder at `programs/<program-name>/` with a `scope.md` (copy `templates/scope.md`). It records the policy URL, the in-scope and out-of-scope assets, and the program's rules.
2. Only test assets listed as in scope there. If a host, IP, app or endpoint is not clearly in scope, stop and ask instead of testing it.
3. When the program's rules are stricter than the defaults below, the program's rules win.

## Rules of engagement (defaults)

- **In scope only.** Check every host, subdomain and IP against `scope.md` before sending traffic to it. Third-party services (CDNs, SaaS, identity providers, payment processors) are out of scope unless the program lists them.
- **No denial of service.** No load testing, flooding or resource exhaustion. Keep request rates low and follow any rate limit the program sets.
- **Your own accounts and data only.** Use test accounts you control. Do not view, change or delete other users' data beyond the minimum needed to prove a bug.
- **Stop on sensitive data.** If you reach real user data, PII, credentials or secrets, stop, record only what proves the issue (redacted), and report it.
- **Minimal proof of concept.** Show the impact, then stop: no pivoting, persistence or data exfiltration.
- **No social engineering, phishing or physical testing** unless the program explicitly allows it.
- **Identify your traffic** the way the program asks (for example a required header or user agent).
- **No disclosure outside the program.** Findings are reported only through the program's own process.

## Secrets and sensitive files

- Never commit API keys, session tokens, cookies, passwords or captured user data.
- Keep secrets in `.env` or under `loot/` (both are gitignored), and redact them in notes and reports.

## Repository layout

```
programs/<program-name>/
  scope.md        # policy URL, in/out of scope, rules (from templates/scope.md)
  notes.md        # running log of recon, ideas and what was tested
  recon/          # recon output (subdomains, endpoints, screenshots)
  findings/       # one file per finding (from templates/finding.md)
templates/        # scope and finding templates
tools/            # scripts and helpers shared across programs
```

## Workflow

1. **Set up the program:** create `programs/<program-name>/` and fill in `scope.md` from the program's policy page.
2. **Recon:** passive first (public sources, docs, JavaScript files), then light active recon against in-scope assets.
3. **Test:** log each idea and what you tried in `notes.md`, including dead ends.
4. **Write up:** one file per finding in `findings/`, using `templates/finding.md`.
5. **Before submitting:** reproduce it again from scratch, confirm the asset is in scope, check the program's list of excluded bug types, and make sure the impact is clearly shown.
