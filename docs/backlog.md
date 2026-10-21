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

## CI and tests

### Harden the Windows test run and the exec exemption
- An intermittent Windows test failure was seen on PR 41 (dc4d232, 032b2f5).
- Require a loadable segment for the exec exemption, and never exempt `activate*` scripts.
- Wrap the CI test log in `::stop-commands::`.
From: PR 41 review.
