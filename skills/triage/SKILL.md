---
name: triage
description: Default pipeline scrutineer runs when a repository is added. Triggers a standard set of other skills in parallel, then writes a short summary of what was enqueued. Edit the list below to change the default scan coverage without touching scrutineer's Go code.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Uses `brief` (github.com/git-pkgs/brief) to classify the repository before deciding which scans to enqueue; falls back to enqueueing everything if brief is unavailable.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# triage

Kick off the standard set of scans against a freshly-added repository.

## Workspace

- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, and `scrutineer.repository_id`. Required.
- `./report.json` — write a short summary of what you enqueued.

## Classify the repository

Run `brief ./src` and read its JSON. Three fields decide which scans are worth queueing:

- `languages` — programming languages detected; `null` or empty means no source
- `package_managers` — manifest/lockfile ecosystems detected; `null` or empty means nothing publishes or consumes packages here
- `layout.source_dirs` — where application/library code lives; `null` or empty means any detected language is incidental scripts

From those, set two flags:

- `has_packages` = `package_managers` is present and non-empty
- `has_code` = `languages` is non-empty AND (`layout.source_dirs` is non-empty OR `has_packages`)

A docs repo (markdown only) has neither. An infrastructure repo (terraform, helm, cloudformation) typically has stray script languages but neither `source_dirs` nor `package_managers`, so `has_code` is false. A real application or library has both. If `brief` is not on PATH or exits non-zero, set both flags true and carry on.

## The scan set

Before enqueueing anything, check what already ran so a re-trigger does not double-enqueue work that is already current.

Get the commit you are running at: `git -C ./src rev-parse HEAD`. Then fetch `GET {api_base}/repositories/{repository_id}/scans`, which returns every scan on this repository with `skill_name`, `status`, and `commit`. Build a set of skill names to skip: a skill goes in the skip set if it has a scan with `status="running"`, or a scan with `status="done"` whose `commit` equals the current HEAD. A `done` scan at any other commit does not count; the repository has moved since then and the skill should run again.

For every remaining skill in the list below, enqueue it: `POST {api_base}/repositories/{id}/skills/{name}/run` with an `Authorization: Bearer {token}` header. Order does not matter; the scrutineer worker runs them as they come in.

If `scrutineer.scan_ref` is set in `context.json`, include it in the POST body as `{"ref": "<value>"}` so child scans clone the same branch. If it is empty, send an empty JSON body or omit the body.

Always:

- `metadata`
- `maintainers`
- `repo-overview`
- `zizmor`

Only when `has_packages`:

- `packages`
- `advisories`
- `dependents`
- `dependencies`
- `sbom`

Only when `has_code`:

- `subprojects`
- `semgrep`
- `security-deep-dive`

If a skill name comes back `404 skill not found or inactive`, skip it and note which one in your report; the operator may have disabled it on purpose.

## Output

Write `./report.json` as:

```json
{
  "has_code": true,
  "has_packages": true,
  "brief": {"languages": ["Ruby"], "package_managers": ["Bundler"], "source_dirs": ["lib", "app"]},
  "triggered": ["metadata", "packages", ...],
  "skipped":   ["semgrep"],
  "gated":     [],
  "already_done": ["metadata"],
  "errors":    []
}
```

`gated` lists skills that were not enqueued because `has_code` or `has_packages` was false. `already_done` holds skills that were skipped because a scan is currently running or already completed at this commit. `skipped` is for skills that came back `404 skill not found or inactive`. `brief` is the subset of brief's output the gates were derived from, so an operator can see why a repo got the short treatment and re-run triage manually if the classification was wrong.

Do not wait for any of the scans to finish. The API returns a scan id immediately; your job is to fire them off and exit.

Do not fabricate scans or invent skill names. If the `api_base` or `token` is missing from context.json, write `{"error": "context.json missing scrutineer block"}` and exit 0 so the failure is visible on the scan page.
