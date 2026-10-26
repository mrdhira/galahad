# Galahad

Galahad inspects untrusted files, links and Git repositories inside an isolated VM before they touch your machine.

It targets the fake-recruiter attacks that ship a "take-home" repo, PDF or archive which runs code when you open it in VS Code, run `npm install`, or start the app.

> Status: v0.2.0. `galahad scan` runs the analysis in its own Firecracker microVM. It needs a Linux amd64 host with KVM. The analysis is static: nothing is run or detonated.

New to the security terms (IOC, defang, sandbox, zip-slip, ...)? See the [glossary](docs/glossary.md).

## Requirements

- A Linux amd64 computer with KVM: `/dev/kvm` must exist and your user must be able to open it. Usually that means being in the `kvm` group (`sudo usermod -aG kvm $USER`, then log out and in). An ACL set with `setfacl` on `/dev/kvm` does not last: systemd-logind rewrites it. In a virtual machine, turn on nested virtualization.
- About 5 GiB of free disk space for the images and the scratch disk of a scan.
- `galahad` and `galahad-agent` side by side in the same directory (the release archives do this). The agent runs inside the VM.
- Network access for `galahad setup`, and for scans of links, Drive files and Git repositories.

macOS and Windows hosts are not supported yet: macOS comes next (M5), Windows after v1.0.0 (M6). There the `galahad scan` command says so.

## Quick start

1. Download the archive for Linux amd64 from [GitHub Releases](https://github.com/mrdhira/galahad/releases) and verify it (see Install below). Unpack it.
2. Check the host. Before the setup this prints FAIL lines that say what is missing and how to fix it:

   ```sh
   ./galahad doctor
   ```

3. Download and verify the pinned Firecracker, the guest kernel and the core image, then fill the ClamAV and YARA signatures through a short update VM. A file that already verifies is not downloaded again, and the signatures are always fetched again:

   ```sh
   ./galahad setup
   ./galahad doctor     # every line is PASS now
   ```

   The images come from the `images-*` release of this repository. `setup --image re` also installs the image for `scan --image re`, which adds capa and Ghidra (Ghidra is installed but not run yet). `setup --skip-signatures` leaves the signatures out; ClamAV and YARA are then left out of scans, and the report says so.

4. Scan something:

   ```sh
   ./galahad scan ./take-home            # a folder
   ./galahad scan ./invoice.pdf          # a file: PDF, Office file, archive, script, binary, ...
   ./galahad scan ./message.eml          # an email: attachments are scanned as child items
   ./galahad scan https://github.com/owner/repo          # a Git repository
   ./galahad scan https://example.com/invoice.pdf        # a file at a link
   ./galahad scan 'https://drive.google.com/file/d/<id>/view'   # a public Google Drive file
   ```

   The scan sends the input into a VM that has no network card, runs the analysis there and prints the verdict, the score and the evidence. The exit code is the verdict:

   | Code | Meaning |
   |---|---|
   | 0 | clean |
   | 10 | suspicious |
   | 20 | malicious |
   | 1 | error |
   | 2 | usage error |

   A `clean` verdict is not a guarantee that the item is safe.

5. Read the reports. Each scan is a job below `~/.galahad/jobs/<id>/`: `report.html` and `summary.md` for people, `report.json` for tools, `proxy.log` with every connection the VM asked for, and `artifacts/`. Links in the HTML and Markdown reports are defanged.

### What a link or a repository means

- `github.com`, `gitlab.com`, `bitbucket.org` and `codeberg.org` repository links are cloned (shallow, hardened, no hooks, no symlinks). Use `--git` to clone any other https link as a repository, and `--submodules` to fetch submodules too. A submodule that points at an address the proxy refuses, such as the cloud metadata address, is reported as `GAL-NET-001`.
- A Drive file link is downloaded in the VM.
- Any other http or https link is downloaded in the VM. A redirect to another host is refused unless you allow that host with `--allow-host <host>` (repeatable).
- The VM reaches the network only through a proxy on the host, which allows the target host, a few fixed hosts, and the hosts you name, resolves names itself and refuses private, loopback and metadata addresses. Every request is logged and shown in the report. `--no-network` serves no proxy at all and is for local files only.
- Links inside an `.eml` are listed in the report; they are not fetched.

### Scan flags

| Flag | Meaning |
|---|---|
| `--image core\|re` | guest image; `re` adds capa for executables (needs `setup --image re`) |
| `--timeout <duration>` | time limit of the whole scan; the default is 10 minutes with `core` and 20 minutes with `re` |
| `--cpus <n>`, `--memory <MiB>` | size of the VM; the defaults are 2 CPUs and 3072 MiB |
| `--allow-host <host>` | let the VM reach one more host |
| `--git`, `--submodules` | see above |
| `--no-network` | no proxy at all |
| `--decision <name>` | ask a decision provider for a second opinion after the scan (see below) |

### Past scans

```sh
./galahad jobs               # list the scans: id, state, verdict, score, date, target
./galahad report <id>        # print the report of a scan again; the exit code is its verdict
./galahad report <id> --json # print report.json
./galahad jobs rm <id>...    # remove scans
```

The state directory is `~/.galahad`, or the directory in `GALAHAD_HOME`. It must be private to you (mode 0700).

## Decision provider (optional)

A decision provider gives a second opinion on a finished scan. It is off unless you pass `--decision`, and nothing leaves your machine otherwise. Galahad speaks the [Netra Decisions API](docs/decision-api.md): it sends the findings and gets back probabilities, not text.

```sh
export NETRA_API_KEY=...                  # the key lives in the environment only
./galahad provider add netra              # the preset: URL, key variable and model
./galahad provider list                   # KEY_SET shows whether the variable is set, never its value
./galahad provider test netra             # one request with a fixed sample that holds no user data
./galahad scan --decision netra ./take-home
```

Any other provider needs `provider add <name> --url <https url> --model <model> [--key-env VAR] [--timeout 60s]`. The config (`~/.galahad/config.json`) stores the name of the variable and never a key. `scan --decision` with an unknown name, an unset key variable or `--no-network` exits 2 before anything boots.

What is sent, after the VM is gone: up to 24 findings of severity low or above (rule ID, severity, title, analyzer, evidence path and line, and the snippet, at most 200 characters), the kind of the target, the file counts and whether the scan was truncated. The target's own name in a path becomes `(target)`. A scan with no such finding sends nothing.

What is never sent: the name or URL of the target, the file list, hashes, IOCs, the network log, the job ID, details of your machine, and Galahad's own verdict and score.

Every string is redacted right before it goes out: AWS, GitHub, Slack, Stripe and other API keys, JWTs, private keys, passwords in URLs, values assigned to names like `password` or `token`, and long high-entropy runs become `[REDACTED:<kind>]`. The patterns are fixed, so a secret in an unknown, low-entropy format can still be sent. The "AI opinions" section of `summary.md` and `report.html` shows the exact request and the redaction counts, so you can check it. The Findings section of the local reports is not redacted.

The cap: an AI opinion never lowers a verdict or a score, and never makes a verdict MALICIOUS. When the provider's `malicious` score is 0.80 or more, a CLEAN scan becomes SUSPICIOUS and the score rises by at most 15 (never above 69). A provider that says "clean" about a MALICIOUS repo changes nothing. If the provider is down, slow, out of credit or answers wrongly, the scan still ends with its own verdict and exit code, and the report says why there is no opinion. A text in the input that tries to steer an AI reviewer is found by the guest (`GAL-INJECT-001`) and the report warns about it.

Cost: the API repeats the input for each of the three questions (verdict, risk, steals secrets), so a call costs about three times the input tokens. The request is at most 64 KiB. Only the verdict answer feeds the score.

Known gaps of the decision provider:
- One provider per scan, with three fixed questions. The scores are model scores, not calibrated probabilities.
- The provider sees findings and short snippets, never whole files, so it cannot find what the analyzers missed.
- Redaction is pattern-based.
- The prompt-injection check reads text files only, not PDF or Office text, and not text hidden by encoding.
- No raw response is stored: an invalid answer is reported by its error code only.

## What it detects

| Problem | What Galahad looks for |
|---|---|
| P1 | Code that runs when you open a folder: VS Code `folderOpen` tasks and devcontainer lifecycle commands |
| P2 | Code that runs at install time: npm lifecycle scripts, husky, pre-commit, pip; typosquatted dependencies |
| P3 | Obfuscated JavaScript and Python (hidden or encoded code), secret theft and exfiltration |
| P4 | Malicious PDFs: auto-run actions, embedded JavaScript, launch actions, URIs |
| P5 | Office macros, remote templates and DDE; LNK files and double-extension tricks inside archives; suspicious binaries |
| P6 | Email lures: attachments are scanned as child items, links are listed, and the sender domain is reported |
| P7 | No false alarms: benign repos and normal PDFs are meant to come out clean |
| P8 | A hostile guest and a hostile input stay contained: the VM has no network card, a read-only root drive, no shared folders, limited processes, memory and disk, and a Result that breaks the protocol is refused and reported as an error |

On top of its own checks the guest runs ClamAV and the YARA-Forge core rules (when the signatures are installed), capa (with `--image re`), and asks OSV whether a pinned npm or PyPI dependency is a known malicious package (`MAL-*` entries only). The OSV lookup needs the network; when you are offline it is left out, and the analyzers listed in the report show that.

The problems are defined in [docs/plan.md](docs/plan.md).

## Known gaps in v0.2.0

- Linux amd64 hosts only.
- Static analysis only. Nothing is executed, so code that hides its behavior until run is not seen. Ghidra is installed in the `re` image but not run.
- No jailer: Firecracker runs as your user, with its own seccomp filters. A Firecracker escape would reach your account.
- A URL that redirects to another host needs `--allow-host`.
- Drive: public single files only. Folders and Google Docs pages are refused.
- Git: https only, no `--ref`, no tree URLs.
- Links in an `.eml` are listed, not fetched.
- OSV: `MAL-*` entries only, for npm and PyPI pins.
- ClamAV and YARA need the signatures from `setup`. The YARA-Forge rules are downloaded by your `setup` and are not redistributed here; they carry mixed licenses, so read the license of the rules you use.
- After a time-out on the host, there is no partial result.
- KVM is tested in CI on one runner type only.
- capa does not finish on large Go binaries in its time limit, so it is left out for them; the report says so.
- The bundled fixtures are the tested baseline. Real-world files can be missed or flagged wrongly. A repo whose only automation is a harmless install script can come out suspicious.
- Archive formats are limited to zip, tar, gzip and bzip2. Files that are too large, encrypted or unsupported are listed as skipped in the report.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/mrdhira/galahad/releases), then verify it with `sha256sum --ignore-missing -c checksums.txt` (macOS: `shasum -a 256 --ignore-missing -c checksums.txt`) and `gh attestation verify <file> --repo mrdhira/galahad`. Do the checks before you unpack the archive. Each archive holds `galahad` and `galahad-agent`. Only Linux amd64 can scan. The release notes link the `images-*` release that `galahad setup` downloads the VM images from.

The guest images are separate works under their own licenses (GPL-2.0 for the kernel, ClamAV and git, for example). The `images-*` release keeps their license files, package lists and source packages.

## Analyzing without a VM manager

`galahad-agent analyze` is the analyzer that runs inside the VM. It reads a folder, a repo checkout, an archive, a PDF, an Office file, an email or a binary and writes `report.json`, `summary.md` and `report.html`. It parses untrusted bytes, so it refuses to run unless it detects a VM (the Galahad guest or any other VM; containers do not count) and exits with code 2. `--unsafe-host` overrides the check and prints a warning. It is risky: a bug in a parser could be exploited by the file you are checking. Use it only for the harmless fixtures in `testdata/corpus/`.

Do not use WSL. All WSL2 distributions and Docker Desktop share one kernel, and WSL can reach your Windows files and start Windows programs. Galahad refuses to run in WSL.

If you run the analyzer by hand in a VM of your own, keep that VM isolated: turn off shared folders, drive redirection and clipboard sharing, keep no credentials or SSH keys in it, and use a throwaway VM or a snapshot.

```sh
./galahad-agent analyze -o out <path>
```

## Development

```sh
make tools   # install golangci-lint, gosec, govulncheck at pinned versions
make build   # build bin/galahad and bin/galahad-agent
make gate    # run the full quality gate
```

Set `SKIP_VULN=1` for `make gate` only where vuln.go.dev is unreachable.

The tests that need a real VM carry the `vm` build tag and run on a KVM runner when started by hand, at the end of each milestone and before each release (`.github/workflows/vm.yml`). The release sweep of popular repositories is a separate workflow that you start by hand (`.github/workflows/sweep.yml`).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
