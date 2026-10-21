# Galahad

Galahad inspects untrusted files, links and Git repositories inside an isolated VM before they touch your machine.

It targets the fake-recruiter attacks that ship a "take-home" repo, PDF or archive which runs code when you open it in VS Code, run `npm install`, or start the app.

> Status: v0.1 is a preview. It is static analysis only, and you must run it inside a VM you already have.

New to the security terms (IOC, defang, sandbox, zip-slip, ...)? See the [glossary](docs/glossary.md).

## Quick start (preview)

v0.1 ships `galahad-agent`, a static analyzer. It reads a folder, a repo checkout, an archive, a PDF, an Office file, an email or a binary and reports a verdict, risk score and evidence. It never runs or detonates anything, and a `clean` verdict is not a guarantee that the item is safe.

The analyzer parses untrusted bytes, so run it inside a VM, not on your real machine:

- macOS: a UTM or Parallels VM.
- Windows: a Hyper-V VM or a WSL2 distribution.
- Any OS: a cloud VM or a throwaway Linux VM.

1. Download the archive for the VM's OS and CPU from [GitHub Releases](https://github.com/mrdhira/galahad/releases) and verify it (see Install below).
2. Copy the suspicious item into the VM. Do not open it on your real machine.
3. In the VM, run:

   ```sh
   galahad-agent analyze -o out <path>
   ```

4. Open `out/report.html` or read `out/summary.md`. `out/report.json` holds the same result for tools. Links in the HTML and Markdown reports are defanged.

The exit code is the verdict:

| Code | Meaning |
|---|---|
| 0 | clean |
| 10 | suspicious |
| 20 | malicious |
| 1 | error |
| 2 | usage error, including a refusal to run outside a VM |

On macOS, Gatekeeper blocks a downloaded binary that is not signed. Remove the quarantine flag once you have verified the download: `xattr -d com.apple.quarantine galahad-agent`.

`galahad-agent` refuses to run when it does not detect a VM. `--unsafe-host` overrides the check. It is risky: the analyzer then parses untrusted bytes on your real machine, so a bug in a parser could be exploited by the file you are checking. Use it only for the harmless fixtures in `testdata/corpus/`.

### What it detects

| Problem | What Galahad looks for |
|---|---|
| P1 | Code that runs when you open a folder: VS Code `folderOpen` tasks and devcontainer lifecycle commands |
| P2 | Code that runs at install time: npm lifecycle scripts, husky, pre-commit, pip; typosquatted dependencies |
| P3 | Obfuscated JavaScript and Python (hidden or encoded code), secret theft and exfiltration |
| P4 | Malicious PDFs: auto-run actions, embedded JavaScript, launch actions, URIs |
| P5 | Office macros, remote templates and DDE; LNK files and double-extension tricks inside archives; suspicious binaries |
| P6 | Email lures: attachments and links are scanned as child items, and the sender domain is reported |
| P7 | No false alarms: benign repos and normal PDFs are meant to come out clean |

The problems are defined in [docs/plan.md](docs/plan.md).

### Limitations

- Static analysis only. Nothing is executed, so code that hides its behavior until run is not seen.
- Galahad does not manage a VM yet. M2 adds `galahad scan`, which runs the analysis in its own VM.
- The bundled fixtures are the tested baseline. Real-world files can be missed or flagged wrongly. A repo whose only automation is a harmless install script can come out suspicious.
- Archive formats are limited to zip, tar, gzip and bzip2. Files that are too large, encrypted or unsupported are listed as skipped in the report.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/mrdhira/galahad/releases), then verify it with `sha256sum --ignore-missing -c checksums.txt` (macOS: `shasum -a 256 --ignore-missing -c checksums.txt`) and `gh attestation verify <file> --repo mrdhira/galahad`. Do the checks before you unpack the archive. Each archive holds `galahad` and `galahad-agent`; for the preview, use `galahad-agent`.

## Development

```sh
make tools   # install golangci-lint, gosec, govulncheck at pinned versions
make build   # build bin/galahad
make gate    # run the full quality gate
```

### Running on the host

`galahad-agent analyze` parses untrusted input, so it refuses to run unless it detects a VM (the Galahad guest or any other VM; containers do not count). Outside a VM it prints a refusal and exits with code 2. Pass `--unsafe-host` to run on the host anyway: it prints a warning and you accept the risk. Use harmless fixtures only.

Set `SKIP_VULN=1` for `make gate` only where vuln.go.dev is unreachable.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
