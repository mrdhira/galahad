# Galahad: full task plan (v5)

## Context
Fake recruiters and phishers send developers PDFs, archives and "take-home" repos. These run code on folder-open (`.vscode/tasks.json`), on `npm install` (lifecycle scripts, husky), or when the app runs, and steal env vars and keys or install malware.

**Galahad** is a single Go **CLI**, released on GitHub. It inspects a link, file or repo inside a VM it manages itself, optionally asks a decision API such as Netra, and writes a summary report (verdict, risk, confidence) and a detailed report. A GUI comes later and will reuse `internal/*`.

## Ground rules (locked)
| Rule | Detail |
|---|---|
| Go | **1.27.3** (`go 1.27.3` in go.mod; CI pins the same) |
| Dependencies | **Go stdlib + `golang.org/x/*` only.** The quality gate enforces this: `go list -m all` must show nothing else. |
| Tools inside the guest VM | Allowed, because they are not linked into the binary: git, ClamAV, YARA, capa, Ghidra, code-server, strace, Sysmon, etc. |
| Host-side tools | Firecracker binary (Linux host), and dev tools (golangci-lint, gosec, govulncheck). Dev tools are installed in CI and **never** added to go.mod. |
| Host safety rule | The host CLI never parses untrusted bytes. All analyzers run in `galahad-agent` inside the VM. |
| Decision API | Netra Decisions API (`model` + `input` + `questions`: choice/score/yes-no → probabilities over fixed labels). Contract in `docs/milestones/M3.md`. |
| Name / repo | **Galahad**, `github.com/mrdhira/galahad`, Apache-2.0. |
| Tests | **Unit tests and black-box acceptance tests only.** No fuzzing and no heavy mocks. |

### Replacing third-party libraries with stdlib / `golang.org/x`
| Instead of | We use |
|---|---|
| cobra | `flag` + a small subcommand router |
| YAML config | JSON config (`encoding/json`) |
| go-git / go-yara | `git` / `yara` CLIs inside the VM |
| firecracker-go-sdk | `net/http` over the Firecracker unix socket |
| Code-Hex/vz (macOS) | our own small cgo + Objective-C bridge to Virtualization.framework |
| hcsshim (Windows) | `golang.org/x/sys/windows` calls into `computecore.dll` (HCS) |
| vsock / hvsock | `golang.org/x/sys/unix` AF_VSOCK; AF_HYPERV via `x/sys/windows` |
| terminal colors / TTY | `golang.org/x/term` |
| HTML parsing (phishing pages) | `golang.org/x/net/html` |
| concurrency | `golang.org/x/sync/errgroup` |
| GoReleaser / cosign | `go build` matrix + `sha256sum` + GitHub `attest-build-provenance` + `gh release` |
| VM networking (tap/iptables on host) | **host-side Go proxy over vsock.** The VM has no NIC. Allowlists, the sinkhole and logging all live in one Go component, with no root needed. |

**CLI exit codes** (useful for scripting): `0` clean · `10` suspicious · `20` malicious · `1` error · `2` usage error.

---

## Skills
Third-party skills live in `.claude/skills/{caveman,ponytail}/`. Before a skill is added or updated, every file is reviewed: no scripts, hooks or network calls, and the license is checked. Skills shape communication and coding style only. They never override the ground rules above.

---

## Development workflow (per task)
```
 PLAN ──► CODE ──► QUALITY GATE ──► CODE REVIEW ──► TEST (QA) ──► DONE
            ▲            │ fail            │ fail          │ fail
            └────────────┴─────────────────┴───────────────┘
```
| Stage | Who | Model / effort | Output |
|---|---|---|---|
| Plan | `planner` agent, once per milestone, plus a short per-task note | Opus 5.5 · medium | Task cards: goal, files, acceptance criteria, linked QA scenarios |
| Code | `coder` agent on branch `feat/T<id>-<slug>` | Sonnet 5.5 · medium | Code + unit tests |
| Quality gate | script `make gate` (**no model**) | none | pass/fail log |
| Code review | `reviewer` agent, fresh context | Opus 5.5 · medium | approve or a list of required changes |
| Test | `qa-engineer` agent | Sonnet 5.5 · medium | black-box acceptance tests run against the built binary |
| Done | squash-merge PR, tick task, update milestone demo script | Haiku 5.5 · low (changelog/notes) | merged |

- **Loop limit:** at most 3 fix loops per task. After that, escalate to Opus (high effort), then to the repository owner.
- **Agent definitions:** live in `.claude/agents/{planner,coder,reviewer,qa-engineer}.md`. Rules and workflow are in `CLAUDE.md`.

### Quality gate (`make gate`, same in CI)
1. `gofmt -l .` → empty
2. `go vet ./...`
3. `golangci-lint run`
4. `go build ./...` for linux/darwin/windows × amd64/arm64
5. `govulncheck ./...`
6. `gosec ./...`
7. `go test -race -count=1 -cover ./...`
8. `go mod verify` + **dependency allowlist check** (only `golang.org/x/*`)
9. acceptance smoke subset (`go test ./test/acceptance -run Smoke`)

### Reviewer checklist
- stdlib/x-only
- the host never parses untrusted bytes
- size, time and path limits on all inputs (zip-slip, bombs)
- errors handled
- the evidence in findings points to file:line
- unit tests cover the behavior
- no real malware in the repo

### QA engineer: what "tested" means
The QA engineer tests **the problem, not the code**. Each scenario traces back to a real attack pattern and runs the **built binary** through `os/exec`, asserting the exit code, verdict, evidence location and report files.

| ID | Problem it answers | Example scenario (Given/When/Then) |
|---|---|---|
| P1 | VS Code folderOpen attack | Repo with `.vscode/tasks.json` `runOn: folderOpen` running `curl … $AWS_SECRET_ACCESS_KEY` → exit 20, evidence `tasks.json:<line>` |
| P2 | npm lifecycle / husky | `postinstall` runs `node scripts/setup.js` that reads `.env` and POSTs it → MALICIOUS (static); in M4, the honeytoken exfiltration is observed |
| P3 | Obfuscated padded JS | Payload hidden after 300 spaces, `eval(atob(...))` → finding "hidden code", deobfuscated snippet in report |
| P4 | Malicious PDF | PDF with `/OpenAction` + `/JavaScript` + `/Launch` → SUSPICIOUS+, URIs listed and defanged |
| P5 | Office / LNK / archive tricks | `invoice.pdf.lnk` in ZIP, OOXML with remote template → flagged |
| P6 | Email lure | `.eml` with attachment + link → child items scanned, sender domain in report |
| P7 | **No false alarms** | Benign repos (express starter, Go CLI, Python lib) and normal PDFs → exit 0 |
| P8 | **Isolation** | Sample tries to read the host path, reach LAN/169.254.169.254, fork-bomb, fill disk → all blocked and reported |
| P9 | Decision API | Mock provider says "benign" on a P1 repo → still MALICIOUS; provider down → scan completes |
| P10 | Safe-work | LAN unreachable from code-server; exported patch flags `.vscode`/binary changes |

The fixtures in `testdata/corpus/` are **harmless imitations**: fake keys, a local sinkhole, and the EICAR test string built at test time (never stored as a file, so antivirus does not flag clones). No real malware.

---

## Milestones, tasks, demos
**62 tasks · 8 milestones · ~27 weeks of effort** (calendar time is likely shorter with agents, but M5 and M6 need manual QA on a real Mac and a real Windows machine).

**Order (owner decision, 2026-10-25):** M0 → M1 → M2 → M3 → M4 → M5 (macOS) → M7 (hardening, v1.0.0) → M6 (Windows, v1.x). v1.0.0 supports Linux and macOS hosts. All Windows host and guest work is in M6, which starts after v1.0.0; until then it is tracked in `docs/backlog.md`. Windows users get the static analysis of Windows files (LNK, PE, Office, scripts) on a Linux or macOS host.

### M0 · Foundation (1 wk, 8 tasks)
| ID | Task |
|---|---|
| T0.1 | Review, install and activate the caveman + ponytail skills |
| T0.2 | Repo bootstrap: `go.mod` (1.27.3), layout, README, LICENSE, .gitignore |
| T0.3 | CLI skeleton (`flag` router): help, `version`, global flags, exit codes |
| T0.4 | `make gate` script, including the dependency allowlist check |
| T0.5 | `ci.yml`: gate on a linux/macos/windows matrix |
| T0.6 | `release.yml`: tag → 6-target build, sha256, provenance attestation, GitHub Release, darwin ad-hoc entitlement signing |
| T0.7 | `CLAUDE.md` + agent definitions (planner, coder, reviewer, qa-engineer) |
| T0.8 | Acceptance harness `test/acceptance` (builds the binary, runs via os/exec) + smoke scenarios |

**🎬 Demo:**
- Tag `v0.0.1`, and GitHub Releases shows 6 binaries with checksums.
- Running `galahad version` and `galahad --help` on your machine works.

**✅ Test:** a CI run is visible on the PR.

### M1 · Static analysis engine + reports, on fixtures only (4 wks, 15 tasks)
| ID | Task |
|---|---|
| T1.1 | Findings/result schema (`protocol`): severity, evidence file:line, snippet, ATT&CK id |
| T1.2 | File identification: magic bytes, hashes, entropy |
| T1.3 | Archive unpacking (zip/tar/gz/bz2) with bomb, depth and zip-slip limits |
| T1.4 | Filename tricks: double extension, RTL override, `.lnk` |
| T1.5 | **Auto-execution inventory** (`.vscode`, devcontainer, husky, pre-commit, npm scripts, Makefile, setup.py/pyproject, build.rs, .envrc, CI) |
| T1.6 | JS/Python obfuscation + exfiltration heuristics (eval/Function, base64 blobs, whitespace padding, env + network together) |
| T1.7 | Dependency checks: lockfiles, typosquats (embedded top-package list), git/tarball dependencies |
| T1.8 | PDF analyzer (objects, FlateDecode, JS/OpenAction/Launch/EmbeddedFile/URI) |
| T1.9 | Office analyzer (OOXML rels/macros/DDE, minimal OLE CFB reader) |
| T1.10 | Binary analyzer (`debug/pe`, `debug/elf`, `debug/macho`: imports, sections, entropy) |
| T1.11 | IOC extraction + defanging |
| T1.12 | `.eml` parser (`net/mail`, `mime/multipart`) → child items |
| T1.13 | Scoring: weights, hard triggers, confidence (coverage, agreement) |
| T1.14 | Reports: `summary.md`, `report.html` (`html/template`), `report.json`, terminal summary (`x/term`) |
| T1.15 | QA: corpus v1 + acceptance tests for P1–P7 |

**🎬 Demo:**
- `galahad-agent analyze --unsafe-host testdata/corpus/fake-interview-repo` → MALICIOUS, with `tasks.json:7` and `scripts/setup.js:3` as evidence. The HTML report opens in a browser.
- The benign repo comes back clean.

This is a dev-only command, used on fixtures only. `--unsafe-host` is needed until M2 runs the agent inside a VM.

### M2 · Linux sandbox and the real `galahad scan` (4 wks, 9 tasks)
| ID | Task |
|---|---|
| T2.1 | Sandbox interface, job lifecycle, `~/.galahad/jobs/<id>` |
| T2.2 | Host↔agent protocol over vsock: length-prefixed JSON, size limits, strict validation |
| T2.3 | Firecracker backend (`net/http` over unix socket): snapshot/copy rootfs, CPU/mem/time limits, teardown |
| T2.4 | Host egress proxy over vsock: allowlist, private ranges blocked, request log |
| T2.5 | Linux guest image build: core image (~300 MB) + optional RE image (Ghidra/capa). Published as release assets with sha256 |
| T2.6 | `galahad doctor` + `galahad setup` (download, verify pinned hashes) |
| T2.7 | Ingest in the guest: URL, Google Drive, hardened git clone, local file/folder (streamed via vsock), `.eml` |
| T2.8 | `galahad scan`, `report` and `jobs` end to end, plus guest tools (ClamAV, YARA, capa, OSV via proxy) |
| T2.9 | QA: P8 isolation suite + P1–P7 rerun through real VMs |

**🎬 Demo:** on a Linux laptop:
- `galahad scan https://github.com/<you>/fake-interview-repo` → MALICIOUS
- `galahad scan ./invoice.pdf` → SUSPICIOUS
- An escape attempt shows as blocked in the report.

**This is the first point where it's safe to point Galahad at real suspicious links.**

### M3 · Decision provider (1 wk, 5 tasks)
| ID | Task |
|---|---|
| T3.1 | JSON config + `provider add/list/test/remove`; keys read from env vars only |
| T3.2 | Decisions API client (`net/http`): timeouts, retry, response validation |
| T3.3 | Snippet selection, secret redaction, prompt-injection detector |
| T3.4 | Capped scoring integration + "AI opinions" report section (what was sent and what came back) |
| T3.5 | QA: P9 with an `httptest` mock provider |

**🎬 Demo:** `galahad provider add netra`, then `galahad scan <repo> --decision netra`. The report shows the AI opinion, and the verdict can't be lowered by a prompt-injection repo.

### M4 · Linux dynamic analysis and safe-work (5 wks, 7 tasks)
| ID | Task |
|---|---|
| T4.1 | Detonation profile: honeytokens (AWS, SSH, `.env`, browser/wallet dirs), realistic user and host |
| T4.2 | In-guest sinkhole: all TCP/DNS redirected to agent fake services; requests and payloads decoded |
| T4.3 | Telemetry: `strace -f` (execve/openat/connect) parsed into a process tree, file and network timeline |
| T4.4 | Scenarios: npm/pip install, folderOpen tasks executed the way VS Code would, start/make, ELF, PDF viewer, Xvfb screenshots |
| T4.5 | Behavior findings → hard triggers (honeytoken exfiltration) |
| T4.6 | Safe-work: `galahad work` (code-server via a vsock port-forward on 127.0.0.1), `--net off|registries`, `work export` patch with flagged files, `work stop` |
| T4.7 | QA: P2 dynamic, P1 dynamic, a delayed payload, P10 |

**🎬 Demo:**
- `galahad scan <repo> --dynamic` → "would have sent AWS_SECRET_ACCESS_KEY to hxxp://…", with the process tree.
- `galahad work <job>` opens VS Code in the browser; editing and exporting produces a patch.

### M5 · macOS host (3 wks, 5 tasks)
| ID | Task |
|---|---|
| T5.1 | macOS backend: our own cgo/Obj-C bridge to Virtualization.framework (Linux boot, virtio-blk, vsock), entitlement signing |
| T5.2 | arm64 guest images (Apple Silicon) alongside amd64 |
| T5.3 | macOS `doctor` checks (macOS 13+, Apple Silicon or Intel, the virtualization entitlement) |
| T5.4 | CI and release: the darwin build needs cgo, so darwin archives build on a macOS runner; unit tests on macOS; a manual acceptance checklist, since GitHub runners can't run nested VMs there |
| T5.5 | QA: full acceptance suite on a real MacBook |

**🎬 Demo:** the same `galahad scan` on your MacBook.

### M7 · Hardening and v1.0.0 (2 wks, 4 tasks), runs after M5
| ID | Task |
|---|---|
| T7.1 | False-positive sweep: about 100 popular repos and PDFs; tune weights |
| T7.2 | Threat model + security review of host code, including the macOS cgo bridge |
| T7.3 | Docs: README, usage, decision-api, threat model |
| T7.4 | `v1.0.0` release + install script |

**🎬 Demo:** a full scripted demo from a clean Linux machine and a clean Mac: install, doctor, setup, scanning the P1–P6 samples, safe-work, and verifying the release checksums.

### M6 · Windows host, Windows guest and Windows dynamic analysis (7 wks, 9 tasks), after v1.0.0
| ID | Task |
|---|---|
| T6.1 | Windows backend: HCS through `x/sys/windows` + AF_HYPERV channel |
| T6.2 | Windows `doctor` checks (Windows Pro or Enterprise, Hyper-V enabled) and a manual acceptance checklist on a real Windows Pro machine |
| T6.3 | `setup --windows`: download Microsoft's evaluation image, prompt for EULA acceptance, unattended provisioning (Sysmon, Acrobat Reader, LibreOffice, Node, Python) |
| T6.4 | Windows build of `galahad-agent`, running as a service with the hvsocket/vsock channel |
| T6.5 | Sysmon telemetry export + `encoding/xml` parsing |
| T6.6 | Scenarios: exe/msi/lnk/js/vbs/ps1, documents, repo scenarios |
| T6.7 | Windows honeytokens (credential files, browser dirs, registry) |
| T6.8 | Snapshot reset + automatic rebuild before the evaluation expires |
| T6.9 | QA: harmless Windows fixtures (a ps1 that reads fake credentials and POSTs to the sinkhole, a `.lnk` → PowerShell, a benign macro) |

**🎬 Demo:** the same `galahad scan` on a Windows Pro laptop, and `galahad scan invoice.pdf.lnk --dynamic --os windows` → MALICIOUS, with the Sysmon process tree.

**Note:** running *Microsoft Office* macros requires your own Office license. By default the Windows guest uses LibreOffice, and static macro analysis always runs.

### Summary
| Milestone | Weeks | Tasks | Demo |
|---|---|---|---|
| M0 Foundation | 1 | 8 | binaries on GitHub Releases |
| M1 Static engine | 4 | 15 | fake-interview repo → MALICIOUS report (fixtures only) |
| M2 Linux sandbox | 4 | 9 | real `galahad scan <link>` on Linux |
| M3 Decision API | 1 | 5 | AI opinion in the report |
| M4 Dynamic + safe-work | 5 | 7 | "would have stolen your AWS key" + browser VS Code |
| M5 macOS host | 3 | 5 | same scan on a MacBook |
| M7 v1.0 (after M5) | 2 | 4 | clean-machine end-to-end demo on Linux and macOS |
| M6 Windows host + guest (after v1.0) | 7 | 9 | same scan on Windows + LNK/PS1 detonation |
| **Total** | **~27** | **62** | v1.0.0 after ~20 weeks |

---

## Repo layout
```
galahad/
├── cmd/galahad/            cmd/galahad-agent/
├── internal/
│   ├── cli/ config/ job/ protocol/ proxy/
│   ├── sandbox/{firecracker,vz,hyperv,fake}/
│   ├── ingest/ analyze/{static,dynamic}/
│   ├── decision/ scoring/ report/ safework/
├── rules/                  # autoexec.json, yara/, embedded
├── images/{linux,windows}/
├── testdata/corpus/        # harmless fixtures
├── test/acceptance/        # black-box tests (QA)
├── .claude/{agents,skills}/  CLAUDE.md
├── .github/workflows/{ci,release,image}.yml
├── Makefile  go.mod  README.md  LICENSE
```
