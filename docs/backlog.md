# Backlog

Follow-ups that are real but outside the scope of the release they were found in. Add new items here instead of widening a PR (see "Scope" in `CLAUDE.md`), and remove an item in the PR that fixes it.

## Archive and Office

### Unpack non-standard parts under OOXML folders
Unpack a skipped `.xml` part whose bytes are not text or XML, and a `vbaProject.bin` whose bytes are not OLE, so content disguised as an OOXML part is still analyzed.

### Archive gaps from the PR 32 review
Follow-ups to the archive analyzer left open by the PR 32 review (archive evasions). Re-check the review notes and close the remaining gaps.
From: PR 32 review.

### Zip with a junk prefix comes out clean
A zip with 1000 bytes of junk in front is CLEAN at confidence 100, while `unzip` still extracts its `.vscode/tasks.json`.

### Symlinked `.vscode/tasks.json` and top-level `.7z`/`.rar` come out clean
A repo whose `.vscode/tasks.json` is a symlink is CLEAN, and a top-level `.7z` or `.rar` is CLEAN at confidence 100. Both should at least lower confidence or be reported.

## Script analyzer

### `.ssh/config` false positive and alias or env-copy evasions
`.ssh/config` and `known_hosts` can still read as secret material in some paths (signals and `segmentNext`). The PR 38 review also listed alias and environment-copy evasions: aliases bound on another line, reassigned aliases, and environment copies through a second variable.
From: PR 38 review.

### Python import flood timing and eval data-flow gaps
A Python file with a flood of imports takes about 9.4 s, close to the 10 s per-file timeout. The eval data flow misses `for-of` over a fetched iterable and `for await` chunks, and flags `argv` after a fetch (false positive).

## Auto-run and dependencies

### Autoexec skips everything under `node_modules/`
autoexec skips any path under `node_modules/`, including archive members, so a zip whose members all sit under `node_modules/` is CLEAN.

### Package-manager config follow-ups
- The `yarn.lock` reader stops only at the per-rule cap (700 MB peak on a 32 MiB lock).
- Poetry typosquat keys are not checked.
- JS comments in `.pnpmfile` are not skipped.
- A `.yarnrc.yml` `plugins` value can raise a false positive.
- `pnpm-workspace.yaml`, `.env.yarn` and prisma paths are not covered.
- Three low findings can add up to a verdict.

### Install-command grader follow-ups
- A committed `node_modules/<tool>` package directory with no `.bin` entry is still rated low. Tests with npm 10.9 and yarn v1 show it is not a working bypass, but adding `node_modules/<pkg>` to the `absentUp` check in `tool()` closes it cheaply and also covers an npm hidden lockfile.
- `.pnpmfile.mjs` is not in `installConfigs`. AUTOEXEC-015 reports it on its own, so the verdict does not change.
- NAME-001 no longer flags `invoice.html.js` or `report.csv.js` inside a zip or an email. Those names could stay decoys for container members, the way the test-folder downgrade already does.
From: PR 45 review.

### Prune the npm list of 404 and holding-package names
Remove names from `top-npm.txt` that now return 404 or are npm security holding packages (web3 spam farms from the npm-high-impact top-dependent source).

## PDF and IOCs

### Keep over-long PDF URIs in IOCs
PDF URIs over the length limit are dropped from the IOC list. Keep the PDF-005 evidence and emit a cut URL, or at least the host.

### Audit eager per-line `EvidenceAt` calls for quadratic cost
autoexec, eml, ioc, office, pdf and script call `analyze.EvidenceAt` per line eagerly. Audit them for quadratic cost on large inputs and compute evidence lazily where needed.

## Protocol and framing

### Frame reads allocate the claimed length
`protocol.ReadFrameOf` refuses a wrong type or an over-limit length on the header, but it then allocates the whole claimed length (up to 64 MiB for a Result) before the payload arrives. Grow the buffer as bytes come in. Callers must set read deadlines.
From: PR 67 review.

### `DecodeStrict` accepts duplicate and case-insensitive keys
`protocol.DecodeStrict` takes duplicate keys (the last one wins) and keys that match a field in a different case, and invalid UTF-8 in a string becomes U+FFFD. `Validate` still runs on the result, but a strict decoder should refuse all three.
From: PR 67 review.

### `Connect.Host` is looser than the proxy policy
`protocol.Connect.Validate` accepts hosts such as `..`, a leading `-` or `.`, and IP literals. The proxy re-checks with its own `validHost`, so nothing gets through today, but any other consumer of `Connect` has to do the same.
From: PR 67 review.

## Sandbox and VM

### Guest tools share uid 1000 with the agent
The agent drops to uid 1000 and the tools it starts keep that uid, so a tool's fork bomb at the full `ulimit -u 512` can starve the Go agent of threads and fail the job (exit 1, no result; a denial, not a false CLEAN). Run the tools under their own uid, for example 1001. Then the P8 fork-bomb probe can drop `bombHeadroom` in `internal/agent/probe_linux_galahadtest.go` and require the job to end done. A JVM tool (Ghidra) has to be watched against the same limit.
From: PR 85 and PR 86 reviews.

### The agent does not set the guest clock
`docs/milestones/M2.md` says the agent sets the clock from `Job.Now` while it is root, but no code does. The kvmclock of Firecracker covers it today. When it is added, it goes before the privilege drop in `internal/agent/guest.go`.
From: PR 84 and PR 86 reviews.

### Update VM leaves the signatures filesystem unclean
The update VM ends the signatures filesystem with `syncfs` and no `umount`, so the superblock is marked unclean. Scans mount it `ro,noload`, which works. Unmount it before the VM stops.
From: PR 86 review.

### A signatures mount failure reaches the host without a progress frame or log
Since the privilege drop, a failure of `signaturesDir` in `internal/agent/guest.go` is returned before the progress frame and without the empty tools-log artifact. Send the progress frame first, or report the failure as an Error frame with the artifact.
From: PR 86 review.

### `CheckDropped` could stand on its own
`agent.CheckDropped` checks uid, euid, gid, egid and that `setuid(0)` fails. It could also re-read the saved ids (`getresgid`) and `getgroups`, so the proof does not rely on the order of calls in `dropPrivileges`.
From: PR 86 review.

### Fake backend's agent inherits the host environment
`internal/sandbox/fake/fake.go` starts the agent with `exec.CommandContext` and no `Env`, so the agent gets every host variable, including a decision provider key such as `NETRA_API_KEY` once M3 lands. Test builds only: a Firecracker guest gets nothing from the host environment. Give the agent a minimal environment (`PATH`, `HOME`, `TMPDIR`, and the test helper variable).
From: M3 planning.

### Fake backend leaks a temp directory per scan
The fake backend starts the agent with `--unsafe-host`, which makes `/tmp/galahad-input-*`. The host kills the agent before its deferred `RemoveAll` runs, so every scan leaves a directory (1724 directories, 1.4 GB, filled a dev disk). Test-only, but it fills CI and dev disks. Give the agent a temp directory that the fake backend removes, or have the agent remove the directory before it sends the Result.
From: PR 86 review.

### `fake.Kill` can block forever
In `internal/sandbox/fake/fake.go`, if `Process.Kill` fails with anything but `os.ErrProcessDone`, `Kill` still waits on `<-m.done`. Return the error or bound the wait. `fake.Start` also overwrites a listener when the same port appears twice and leaks the first one. Test-only.
From: PR 66 review.

### Firecracker backend hardening
- Add a comment near `Pdeathsig` in `internal/sandbox/firecracker/machine.go`: never start Firecracker from a goroutine that calls `LockOSThread` and returns, since the thread exit kills the VM.
- `capWriter` returns an error after a failed write, which stops the copy and can block Firecracker on a full pipe. Keep returning `len(p)` and drop the rest.
- Add unit cases for `makeScratch`, console open and `MkdirTemp` failures.
From: PR 73 review.

### P8 vsock probe accepts the same errors for every CID
`checkVsock` in `test/acceptance/p8_test.go` accepts `ECONNRESET`, `ECONNREFUSED`, `ENODEV` and `timeout` for every address. Require reset, refusal or timeout for host CID 2, and allow `ENODEV` or `ETIMEDOUT` only for other CIDs. Today a kernel `ETIMEDOUT` and the Go-side wait both read "timeout", so a kernel timeout on host CID 2 passes too.
From: PR 85 review.

## Guest tools (ClamAV, YARA, capa, OSV)

### `clamscan` exit 2 with output but no parsed hit is an error
In `internal/analyze/tools/clamav.go`, exit 2 with stdout that parses to no finding is reported as a tool failure and the output is dropped. Treat it like exit 1: add a finding with the snippet "unparsed clamscan hit". The fallback finding path for a directory target is `filepath.Base(root)`, which reads like a file; use a clearer marker.
From: PR 79 and PR 84 reviews.

### Coverage does not say why it is truncated
`Coverage.Truncated` is set both by a limit and by a tool that was left out, and the report uses shared wording for the two. The scoring reasons now name each tool in `Coverage.LeftOut` and its cause; the Truncated line of the report still uses the shared wording. The timeout message in `execute` (`internal/analyze/tools/tools.go`) also rounds to whole seconds.
From: PR 79 review.

### capa turns itself off after the first timeout
`internal/analyze/tools/capa.go` stops at the first timeout, so one slow executable that sorts first leaves capa out for all later files. Scan the smallest files first. There is no unit case for "an earlier capa hit is kept after a later timeout"; the fake capa needs a per-file mode for it.
From: PR 83 review.

### capa out of total time reads as "failed"
When capa runs out of its total time before it has examined any file, `internal/analyze/tools/capa.go` reports the cause as `failed`, not `timeout`, so the reason says "capa was left out: it failed". Return the timeout error in that case too.
From: PR 91 review.

### The OSV block reason is said twice
When the proxy refuses the OSV lookup (a fake-IP or Pi-hole DNS), the reasons list both "the OSV lookup was blocked: ..." and "osv was left out: it failed, see artifacts/tools.log". Keep one line that names the block.
From: PR 91 review.

### capa cannot read Mach-O and is near its limit on large binaries
capa has no Mach-O support, so it always fails on those files. On large Go binaries it does not finish: the 9.6 MB `galahad` binary ran past both 60 s and 5 min in the v0.2.0 sweep, so capa is left out (coverage is truncated, the exit code stays 0). This is a known gap in v0.2.0. Skip Mach-O files up front, and find a capa mode or option that finishes on Go binaries, or skip them with a clear note.
From: PR 83 review, v0.2.0 sweep.

### `walkJSON` copies the key path for every member
`walkJSON` in `internal/analyze/static/deps/deps.go` copies the whole key path for every string member: a 31 MiB lockfile nested 32 deep allocates about 3.5 GB in total. The OSV tool parses the same file a second time. Share the path or parse once.
From: PR 83 review.

### Per-file timing test can flake under load
The pdf `TestAnalyze` case "thousands of URIs deep in a large file" can hit its deadline under heavy load (seen at load 11). Give it more headroom, or count work instead of time.
From: PR 69, PR 70 and PR 71 re-reviews.

### YARA-Forge webshell rule fires on a TypeScript file
`SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval` matched `fsprovider-sample/src/extension.ts` in microsoft/vscode-extension-samples in the v0.2.0 sweep and raised its score from 20 to 35 (GAL-YARA-001, medium). The rule is meant for PHP files. Scope PHP rules to PHP files, or leave this rule out of the compiled set.
From: v0.2.0 sweep, PR 88 review.

### ClamAV can take the time of the later tools
ClamAV may now use 5 minutes (`internal/analyze/tools/clamav.go`). On a 10-minute core job with a slow clone, YARA or OSV can then run out of time; they are left out with a reason and the coverage is truncated. Give each tool a share of the remaining time instead of fixed limits.
From: PR 88 review.

### capa fallback path has no unit test
The fallback to `/opt/capa/capa` in `internal/analyze/tools/capa.go` needs a file at that path, so no unit test covers it; the release sweep does. A guest tool hit without evidence also prints as `GAL-YARA-001  in ` in the sweep notice (`scripts/vm/sweep.sh`).
From: PR 88 review.

## Ingest (URL, Drive, Git)

### Ingest gets no time share
The host sends only `Timeouts.Job`, so the guest gives ingest the whole job time. A clone plus a submodule update (5 minutes each) can use up the 10 minute default. Send a `Timeouts.Ingest` share. Also, `ingest.Extract` checks the limit once per tar entry, so a host that stalls mid-stream can overrun the share by up to the 60 s idle limit.
From: PR 81 review and PR 69/70/71 re-reviews.

### Git timeout kills only git
`internal/ingest/git.go` kills git on timeout and sets `WaitDelay`, but does not kill the helper processes git started. Set `Setpgid` and kill the process group, as `internal/analyze/tools/group_unix.go` does.
From: PR 81 review.

### Git error codes come from stderr text
`ErrTooLarge` and `ErrNotAllowed` are chosen by matching git's stderr, so a hostile server can pick them with `remote:` lines. It fails safe (the job still fails), but the server chooses the message.
From: PR 81 review.

### Bare `filename=` with raw UTF-8 falls back to the URL name
A Content-Disposition header with an unquoted raw UTF-8 `filename=` (for example one with an RLO character) fails `mime.ParseMediaType`, so `rawName` in `internal/ingest/url.go` uses the URL path. Browsers keep the header name. Add a fallback that reads a bare `filename=` value. Test cases are also missing for a raw name taken from the URL path with no header, and for the Sheets and Slides message.
From: PR 82 review.

### `CleanName` keeps Windows-forbidden characters
`ingest.CleanName` keeps `: * ? " < > |`. Only the fake backend runs on Windows, so this does not matter in the VM, but a fake-backend download on Windows can fail to create the file.
From: PR 81 review.

### Label the link target hash as reported by the sandbox
For a link, `Target.SHA256` comes from the guest, not from the host. Say "reported by the sandbox" next to it in the reports (`internal/report/markdown.go` and the terminal and HTML output).
From: PR 80 review.

### Refuse unusable link hosts before booting
`galahad scan` should exit 2 up front for a link host that the proxy policy refuses (IPv6, `_`, trailing dot) and for a port other than 80 or 443, instead of failing in the VM. For a non-ASCII host, the message should tell the user to use punycode.
From: PR 80 review.

## Proxy and network

### Count the requests that are not listed
Add `Network.Unlisted`, the number of blocked decisions that did not fit in the event list plus the over-cap and bad-frame closes, and render it as "N more requests not listed".
From: PR 75 review.

### Relay stops on a temporary `Accept` error
In `internal/agent/relay.go`, `Serve` returns on any `Accept` error that is not a shutdown, so one `EMFILE` ends the relay for the whole job. Retry temporary errors with a backoff.
From: PR 75 review.

### Well-known names are refused as "host not allowed"
`localhost`, `metadata.google.internal` and `169.254.169.254.` are refused by `vet` in `internal/proxy/proxy.go` as "host not allowed" or "bad host name", never as GAL-NET-001. Block the well-known names before the policy check so they are reported as blocked.
From: PR 75 review.

### Network section for `--no-network`
With `--no-network` the Network section says "None." Say "network disabled" instead (`internal/report/markdown.go` and the other renderers).
From: PR 75 review.

### Update jobs set `blocked` from infrastructure hosts too
For an update or probe job, `runner.finish` in `internal/job/run.go` sets `job.Blocked` from every blocked proxy event, including the fixed infrastructure host that scan jobs exempt through `countsAsBlocked`. Nothing reads the field for those jobs yet. Use `countsAsBlocked` there too before something does.
From: PR 85 review.

## Host job, report and CLI

### A limit cut is not named next to a left-out tool
`internal/scoring/scoring.go` adds "a limit cut the analysis short" only when no guest tool was left out. A scan cut by a file or finding limit, or by a tool that ran only in part, and that also left a tool out, shows only the tool line. The confidence is right; the reason is incomplete. Record a limit cut separately from `Coverage.Truncated` so both can be named.
From: PR 91 review.

### M1.md shows the old Coverage and reason text
`docs/milestones/M1.md` lists `Coverage` without `left_out` and quotes the old generic reason "a limit or a guest tool that did not run cut the analysis short". Update both, or mark them as the v0.1.0 state.
From: PR 91 review.

### `newPlan` ignores the context
`newPlan` in `internal/job/input.go` walks the target without a context, so Ctrl-C does nothing during the host walk. The walk is bounded by 200000 entries but slow on a network file system. The pre-boot size estimate also counts one header block per entry and ignores PAX and GNU long-name blocks, so an input near the cap with long names fails after boot (still exit 1).
From: PR 72 review.

### Result target name is not bound to the name the host sent
The host checks `Result.Target.Kind` and the sha256, but not that `Result.Target.Name` is the name it sent. Compare them in `internal/job/run.go`.
From: PR 72 review.

### `report.Write` can exceed the size `galahad report` reads
`report.Write` indents the JSON and escapes HTML, so a Result near the 64 MiB frame cap can grow past the 64 MiB read cap in `internal/cli/report.go`. Write it compact, or derive the read cap from the worst-case growth.
From: PR 74 review.

### `job.Load` trusts the fields of `job.json`
`job.Load` keeps `Target.Input` and `Error` from `job.json` up to the 1 MiB file cap, so 10 000 tampered jobs make about 10 GiB for `galahad jobs`. Cap the fields in `Load` and check `Verdict` against the allowed values.
From: PR 74 review.

### `galahad report` accepts an empty verdict
`protocol.Result.Validate` accepts an empty verdict, so `galahad report` prints "Verdict: " and exits 0. Refuse it, or score the Result again and refuse a mismatch.
From: PR 74 review.

### `scan` does not take flags after the target
`runScan` uses plain `fs.Parse`, so `galahad scan <path> --timeout 5m` is a usage error, while `jobs` and `report` accept flags after arguments. Make the three behave the same.
From: PR 74 review.

### Job store details
- `job.ReadFile` reports a failing `f.Stat()` as "not a regular file". Wrap the `Stat` error separately.
- `job.Save` writes a fixed `job.json.tmp`, and a stale file from a crash keeps its wider mode through `Save`. Remove the old file first, or use `os.CreateTemp`.
From: PR 66 and PR 74 reviews.

### Fixed temp name for the signatures stamp
`writeStamp` in `internal/job/update.go` writes `<stamp>.tmp` with `os.WriteFile`, which follows a symlink and collides with a concurrent `galahad setup`. Use `os.CreateTemp` in the same directory.
From: PR 84 review.

### `galahad doctor` agent check hardening
In `internal/cli/doctor.go`, set `cmd.WaitDelay` in `agentVersion` so `io.ReadAll` cannot outlive the 10 s limit.
From: PR 84 review.

## Images and setup

### Pin the Firecracker binary hash
`internal/images/pins.json` pins the sha256 of the Firecracker archive only. `setup` and `doctor` trust `firecracker --version` for the installed binary. Pin the sha256 of the extracted binary and check it in `images.VerifyFirecracker`.
From: PR 78 review.

### `VerifyAsset` hangs on a FIFO
`images.VerifyAsset` opens the file before `Stat`, so a FIFO at an image path hangs `setup` and `doctor`. Use `Lstat` first, or open with `O_NONBLOCK`.
From: PR 78 review.

### Setup state directory permissions and leftovers
- `setup` creates `home`, `bin` and `images` with `MkdirAll(0o700)`, which does not tighten existing directories, and `doctor` checks only `home`.
- `.part` files left by a SIGKILL are never cleaned; with `--image re` they can reach about 2.3 GiB.
- `DownloadTimeout` is 30 minutes for the whole download, which needs at least 3.1 Mbit/s for the 696 MB `re.ext4.gz`. Use a stall timeout, or scale the limit by the size.
From: PR 78 review.

### Image build details
- The kernel build step in `.github/workflows/image.yml` does not need `--privileged`.
- `mmdebstrap` in `images/linux/build.sh` could use `--skip=essential/unlink`, so the deb cache keeps the essential packages (faster, and fewer snapshot rate limits).
- GPL source selection in `gpl_sources` ignores `Built-Using` and `Static-Built-Using` (for example the Rust crates of ClamAV).
- `gpl_sources` downloads every core source package again for the re image, with no cache. Watch the 120 minute job limit.
- `fetch` caches by the URL basename, so after a capa version bump the `image-cache-` restore key can bring back an old `LICENSE.txt` that fails the pin check on every run. Name cache files by version or hash.
- `re.ext4` is exactly at the 1536 MiB cap, and the 64 MiB rounding in `image_mib` hides the headroom. Prune the non-linux Ghidra `os/` directories or the JDK jmods.
- The capa PyInstaller bundle ships no notices for its MIT and BSD Python dependencies.
From: PR 68 and PR 71 reviews.

### Firecracker 2.0 drops legacy boot
Firecracker 2.0 drops the legacy boot path, which needs `ACPI=y` and `PCI=y`. `images/linux/kernel/build.sh` forbids PCI today and the kernel config sets neither. Plan the kernel change before the pin moves to 2.0. Consider `RANDOM_TRUST_CPU` for early `getrandom` too.
From: PR 68 review.

## CI and tests

### Harden the Windows test run and the exec exemption
- An intermittent Windows test failure was seen on PR 41 (dc4d232, 032b2f5).
- Require a loadable segment for the exec exemption, and never exempt `activate*` scripts.
- Wrap the CI test log in `::stop-commands::`.
From: PR 41 review.

### Tagged tests run on Linux only
The `galahadtest` unit tests run only in the Linux gate step. The macOS and Windows CI jobs run untagged, and `gosec` runs untagged, so it never scans `internal/sandbox/fake/fake.go` or the other test-build files. Run `gosec` with `-tags galahadtest` as well.
From: PR 66 review.

### Missing job and store test cases
- `TestRun` in `internal/job/run_test.go` has no case for a target that is a symlink, the filesystem root, the entry cap, "changed while it was read", a write failure followed by grace expiry, or an artifact I/O error.
- No test pins the `O_NONBLOCK` open in `job.copyFile`. Add a case that swaps a file for a FIFO without cancelling and expects "changed while it was read" (about 5 s, the write grace).
- In `internal/job/store_test.go` the oversize case comes before the decode cases, and the `Create` branches (ID retry, `Save` failure, no free ID) are not covered.
From: PR 66 and PR 72 reviews.

### Proxy and vsock test cleanups
- `TestServeBadConnect` in `internal/proxy/proxy_test.go` sets `wantMaySeeReset`, which is probably unnecessary (the oversize Result sends only the 5-byte header). Drop it so the case requires the reply.
- `TestDial/loopback_listener` skips without vsock loopback, so the `os.File` deadline path is untested until a VM test covers it. The host `CloseWrite` drain on the real vsock path is not tested either.
- `TestRunNetwork` in `internal/job/network_test.go` has the `NoNetwork` case after the `finish()` rejection cases. In code order it comes first.
From: PR 69, PR 70 and PR 75 reviews.

### Test order nits in setup, update and ingest tests
- `TestInstallAssetAfterAFailure` is not table-driven, and `TestInstallAsset` has the not-gzip case before the bomb case (`internal/images/download_test.go`).
- The first case of the acceptance `setup_test.go` is a failure case.
- `internal/agent/update_test.go` has the no-proxy and no-drive cases before the freshclam cases.
- `TestRawName` and `TestGuestRemote` are out of code order.
From: PR 78, PR 82 and PR 84 reviews.

### `vmtest.sh` output
`scripts/vm/vmtest.sh` prints the `--- PASS/FAIL` lines without `tr -cd '[:print:]\n'`. Add it so a `\r` in a test name cannot split a line into a workflow command.
From: PR 87 review.

## Decision provider (M3)

### Sweep targets promptfoo and garak are MALICIOUS before any M3 change
Decide this in T3.5, before v0.3.0. The M3 definition of done says `promptfoo/promptfoo` and `NVIDIA/garak` must not be MALICIOUS, but `galahad-agent analyze` on main already gives:
- promptfoo: MALICIOUS from GAL-EXFIL-001, GAL-EXEC-001 and others;
- garak: MALICIOUS from GAL-SIG-001 (critical) and GAL-DEPS-001 (high).

garak also gets one `GAL-INJECT-001` medium at `garak/data/inthewild_jailbreak_llms.json:34`, a real jailbreak prompt in its dataset. Both repos ship attack samples on purpose. Run the full sweep first (CLAUDE.md, Scope), then either fix real false alarms or narrow the definition of done for repos that carry samples, with the owner's approval.
From: PR 98 review.

### Provider config hardening
- `Load` does not compare the opened file with the `Lstat` result, so a symlink swapped in between them is followed. Refuse unless `os.SameFile`, or open with `O_NOFOLLOW` (`internal/config/file.go`).
- `encoding/json` matches field names without regard to case, and a duplicate key takes the last value. Neither lets a key in.
- `validateURL` keeps `HTTPS://` as typed and accepts port 99999 or an empty port. Lowercase the scheme and require a port of 1 to 65535.
- Two concurrent `provider add` or `remove` runs can lose an update (no lock), and the parent directory is not fsynced after the rename in `Save`.
From: PR 95 review.

### Provider command tests
- `TestSave` and `TestProvider` cases are not in code order, and `TestLoad` has no case for an `Lstat` or `OpenFile` error other than not-exist.
- `test/acceptance/provider_test.go` has no hostile-config cases through the binary (an `api_key` field, 17 providers, version 2, a 70 KiB file, a symlink, a FIFO), no `KEY_SET no` case, one exit-2 case only, no `--key-env` case, and no single run that adds a provider, lists it, then removes it in the same home.
From: PR 95 review and QA.

### Decision contract details
- A nil `Findings` encodes as `null`, and `DecisionRequest.Validate` accepts a sent request with no findings. Require 1 to 24.
- An empty `analyzer` or `title` is accepted inside `sent`.
- `encoding/json` matches response keys without regard to case (`"OBJECT"`); every value is still checked.
- In `decision_test.go`, `TestDecisionQuestions` and `TestDecisionRequestKeys` check things outside the table, and `TestParseDecisionResponse` cases are not in code order.
From: PR 96 review.

### Prompt-injection detector gaps
- UTF-16 text files are not read (they hold NULs), and one NUL in the first 8 KiB hides the whole file.
- Invisible characters outside the listed set get through: U+00AD, U+200E and U+200F and other bidi marks, U+2061 to U+2064, and tag characters U+E0000 to U+E007F. NBSP inside a phrase and homoglyphs also get through.
- Markup or comment prefixes inside a phrase are missed: `Do **not** flag`, `// ignore all` then `// previous instructions`.
- The patterns have no leading word boundary, so `undo not report` matches.
- Go's `\s` does not include `\v`.
- The test-folder downgrade applies to archive members too. Decide in T3.5 whether to also downgrade test file names (`_test.go`, `.spec.ts`, `test_*.py`); the galahad repo's own `inject_test.go` gets medium hits today.
- Without a match cap, a dense 32 MiB text file with no pair takes about 2.9 s, against the 10 s per-file timeout. Many such files add up against the 5-minute job timeout; keep it in mind when sizing the guest CPU.
- The test helper `cmpOr` duplicates `cmp.Or`.
From: PR 98 review.

## Windows (M6, after v1.0.0)

### Windows host and Windows guest
The owner moved all Windows work after v1.0.0 (2026-10-25). v1.0.0 ships Linux and macOS hosts. On Windows, `galahad.exe` builds and runs, but `scan` refuses with a clear message until M6. The M6 cards are in `docs/plan.md`: the HCS backend and AF_HYPERV channel, Windows `doctor` checks, the Windows evaluation guest with Sysmon, the Windows agent service, Windows detonation scenarios and honeytokens, snapshot reset, and QA on a real Windows Pro machine. Update `README.md` to state the supported hosts when the plan change reaches the docs (`README.md:18` still says macOS and Windows hosts are not supported yet).
- The refusal message still says "Linux only until M5" on every non-Linux host (`internal/sandbox/firecracker/firecracker_other.go`, `internal/cli/cli.go`, `internal/cli/diskfree_other.go`, and their tests in `doctor_test.go` and `setup_test.go`). Give a message per OS, so Windows says M6, and update `docs/milestones/M2.md` to match.
From: owner decision on the milestone order, and the PR 97 review.

### Scan from WSL2 on Windows
Windows 11 exposes `/dev/kvm` to WSL2 when nested virtualization is on, so the Linux binary and Firecracker may run inside WSL2. Test it on a real Windows 11 machine, and if it works, document it as the way to use Galahad on Windows before M6. `README.md` and `docs/glossary.md` say Galahad refuses to run in WSL, but only `galahad-agent analyze` checks for it (`internal/vmguard`); narrow that wording to the agent if the test works.
From: owner decision on the milestone order, and the PR 97 review.
