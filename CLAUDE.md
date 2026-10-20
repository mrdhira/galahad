# Galahad: working rules

Galahad is a Go CLI that inspects untrusted files, links and Git repositories inside an isolated VM and reports a verdict, risk score and confidence. The full plan, milestones and task IDs are in `docs/plan.md`.

## Hard rules
- Go version: 1.27.3 (`go.mod` pins it).
- Imports: Go standard library and `golang.org/x/*` only. No other module may appear in `go list -m all`. `make gate` enforces this.
- Dev tools (golangci-lint, gosec, govulncheck) are installed separately. Never add them to `go.mod` (no `tool` directive).
- The host binary (`cmd/galahad`) never parses untrusted bytes. Parsing and analysis code runs in `cmd/galahad-agent` inside the guest VM. The host only moves bytes, computes hashes, controls jobs and renders validated JSON results.
- Every input reader has size, depth, time and path limits (zip-slip, decompression bombs).
- Never commit real malware. Fixtures in `testdata/corpus/` are harmless imitations.
- Skills: use `caveman` (full) for chat and `ponytail` (full) for code. Code, comments, commits and docs are written in plain, normal prose.

## Commits and pull requests
- Author: `Dhira Wigata <dwigata.putra@gmail.com>`. Nobody else. Exception: `dependabot[bot]` may author dependency-bump commits from its own PRs.
- No `Co-Authored-By` lines, no AI or tool attribution, no session links in commits, PR titles, PR bodies or docs.
- Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `ci:`, `refactor:`.
- One branch and one PR per task: `feat/T<id>-<slug>` (for example `feat/T1.5-autoexec`). Squash-merge when the workflow below passes.

## Workflow per task
```
PLAN -> CODE -> QUALITY GATE -> CODE REVIEW -> TEST (QA) -> DONE
          ^          | fail          | fail          | fail
          +----------+---------------+---------------+
```
| Stage | Who | Model, effort |
|---|---|---|
| Plan | `planner` agent (per milestone) | opus, medium |
| Code | `coder` agent | sonnet, medium |
| Quality gate | `make gate` (script, no model) | none |
| Code review | `reviewer` agent, fresh context | opus, medium |
| Test | `qa-engineer` agent | sonnet, medium |
| Done | squash-merge, update notes | haiku, low |

At most 3 fix loops per task. After that, escalate to opus with high effort, then to the repository owner.

## Quality gate
`make gate` runs, in order: `gofmt -l`, `go vet`, `golangci-lint run`, cross-build for linux/darwin/windows x amd64/arm64, `govulncheck`, `gosec`, `go test -race -count=1 -cover ./...`, `go mod verify` plus the dependency allowlist, and the acceptance smoke tests. CI runs the same target.

## Tests
- Unit tests: table-driven, next to the code, no heavy mocks.
- Acceptance tests: `test/acceptance/`, black-box. They build the binary and run it with `os/exec`, then assert exit code, verdict, evidence and report files.
- Acceptance scenarios trace to the problems P1-P10 in `docs/plan.md`. A green unit suite that does not answer those problems is not done.
- No fuzzing, no e2e frameworks.

## Exit codes
`0` clean, `10` suspicious, `20` malicious, `1` error, `2` usage error.

## Layout
```
cmd/galahad/          host CLI
cmd/galahad-agent/    in-guest agent
internal/             cli, config, job, protocol, proxy, sandbox, ingest, analyze, decision, scoring, report, safework
rules/                embedded detection rules
images/               guest image build scripts
testdata/corpus/      harmless fixtures
test/acceptance/      black-box tests
docs/                 plan and design docs
```
