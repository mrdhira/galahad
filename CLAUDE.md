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
- `main` is protected: one approving review and green `gate`, `test (macos-latest)` and `test (windows-latest)` checks. The repository owner authorized merging with the owner bypass only when the reviewer agent approved, QA passed and all CI checks are green on the PR head. Never bypass on red CI or an open review finding.

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

## Scope
- Each release has a written definition of done before work starts: the problems it must answer, the repos it must keep clean, and the known gaps it may ship with. Work outside that list waits for the next release.
- One PR has one purpose. A finding outside that purpose becomes a backlog item, not a new commit on the PR. The backlog is `docs/backlog.md`: add the item there, and remove it in the PR that fixes it.
- A review finding blocks a PR only when it is one of these:
  1. a regression against `main`;
  2. a bypass of exactly what the PR claims to fix;
  3. a false alarm on a common, popular repo;
  4. a crash or a hang.
  Everything else is a follow-up in the backlog.
- A violation of a Hard rule or of the commit and attribution rules always blocks, whatever the bar above says.
- Only `CHANGES REQUIRED` items count as open review findings. Follow-ups listed with an `APPROVE` do not block the merge; add them to `docs/backlog.md`.
- PRs that touch the same files merge one at a time. The next one merges `main` into its branch and runs `make gate` before its review.
- Run the false-positive sweep on popular repos before tuning detection, so the fixes target real false alarms.

## Quality gate
`make gate` runs, in order: `gofmt -l`, `go vet`, `golangci-lint run`, cross-build for linux/darwin/windows x amd64/arm64, `govulncheck`, `gosec`, `go test -race -count=1 -cover ./...`, `go mod verify` plus the dependency allowlist, and the acceptance smoke tests. CI runs the same target. On a pull request that only changes docs (Markdown under `docs/` and `.claude/`, skill `LICENSE` files, top-level Markdown, `LICENSE`, `.gitignore` or the Dependabot config), the `gate` and `test` jobs skip their steps but still report, so the required checks pass quickly. If the change detection fails, everything runs. Pushes to `main` always run in full.

## Tests
- Unit tests sit next to the code and are black-box: `package <name>_test`, exported API only. White-box tests (`package <name>`) are not used for now.
- Acceptance tests: `test/acceptance/` (`package acceptance_test`). They build the binary and run it with `os/exec`, then assert exit code, verdict, evidence and report files.
- Acceptance scenarios trace to the problems P1-P10 in `docs/plan.md`. A green unit suite that does not answer those problems is not done.
- No fuzzing, no e2e frameworks, no heavy mocks.

### Table-driven shape (all unit and acceptance tests)
Every test function is table-driven with the same shape:

```go
func TestRun(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations, each prefixed with "want"
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version prints build info", args: []string{"version"}, wantCode: 0, wantStdout: "galahad"},
		// ...
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// arrange, act, assert
		})
	}
}
```

- Field order: `name`, then inputs, then `want*` fields. Cases use keyed fields.
- The loop variable is `tt`; every case runs in `t.Run(tt.name, ...)`.
- Case order: the full success path first. Then one case per branch, in the order the branches appear in the code from top to bottom, whether that branch succeeds or fails.

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
