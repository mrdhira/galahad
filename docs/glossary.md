# Glossary

Security and project terms used in Galahad's code, reports and docs, in plain language. Terms are grouped by topic and sorted alphabetically within each group.

## Attacks and threats

**Auto-execution**
: Code that runs without you choosing to run it, just because you opened a folder, installed dependencies or made a commit. Examples: a VS Code task with `runOn: folderOpen`, an npm `postinstall` script, a git hook. This is the main trick in fake take-home assignments.

**Bidi / RTLO (right-to-left override)**
: Invisible Unicode characters that flip the display order of text. `invoice<RTLO>fdp.exe` displays as `invoiceexe.pdf`, so an executable looks like a PDF. Galahad shows these characters as visible escapes such as `‮`.

**Decompression bomb (zip bomb)**
: A small archive that expands to an enormous size (for example 1 MB that unpacks to 100 GB) to crash or freeze the tool that opens it.

**DDE (Dynamic Data Exchange)**
: An old Office feature that lets a document field run a command. Attackers abuse it to run programs without macros.

**Double extension**
: A file name like `invoice.pdf.exe` or `photo.jpg.lnk` that hopes you only notice the first extension.

**Exfiltration**
: Sending stolen data (environment variables, SSH keys, cloud credentials, crypto wallets) out to an attacker-controlled server.

**LNK file**
: A Windows shortcut file. It can launch PowerShell or other programs with arbitrary arguments, so it is often used as a disguised payload.

**Macro (VBA)**
: Code embedded in Office documents. `AutoOpen` or `Document_Open` macros run when the document is opened if macros are enabled.

**Obfuscation**
: Hiding what code does: base64- or hex-encoded strings, `eval` of decoded text, or code pushed far off-screen after hundreds of spaces.

**Payload**
: The part of an attack that does the actual harm, for example the script that steals keys or downloads malware.

**Phishing**
: Tricking someone into opening a file, clicking a link or entering credentials. Fake recruiter emails and "take-home tests" are a common form aimed at developers.

**Process injection**
: Malware running its code inside another, legitimate process to hide. Certain Windows API combinations are a strong signal of it.

**Remote template injection**
: A Word document that loads its template from an attacker's URL when opened. The remote template can carry macros even though the document itself contains none.

**Supply-chain attack**
: Compromising the things you install (packages, dependencies, build tools) instead of attacking you directly.

**Typosquatting**
: Publishing a malicious package with a name one typo away from a popular one, such as `expresss` instead of `express` or `reqeusts` instead of `requests`.

**Zip-slip (path traversal)**
: An archive entry named like `../../.bashrc` that, if extracted naively, writes outside the target folder.

## Analysis and reports

**ATT&CK (MITRE ATT&CK)**
: A public catalogue of attacker techniques with IDs like `T1204.002` (user runs a malicious file). Each Galahad finding carries an ATT&CK ID so results can be compared with other tools.

**Confidence**
: How sure Galahad is about the verdict (0–100, and low, medium or high). It drops when files could not be analyzed and rises when several independent analyzers agree.

**Coverage**
: The share of files Galahad actually analyzed. Files that were too large, encrypted or unsupported lower coverage, and the report lists them.

**Defang**
: Rewriting a dangerous link so it cannot be clicked or auto-opened, while staying readable. `https://evil.test/x` becomes `hxxps://evil[.]test/x`, and `a@evil.test` becomes `a[@]evil[.]test`. Galahad defangs every link in `summary.md`, `report.html` and terminal output. `report.json` keeps the raw value for tools.

**Dynamic analysis (detonation)**
: Actually running a sample inside a sealed VM and watching what it does. Planned for M4 and later.

**Entropy**
: A measure of randomness in data (0–8 bits per byte). Very high entropy in executable code often means it is packed or encrypted.

**Evidence**
: Where a finding was seen: a path plus a line number (`.vscode/tasks.json:7`) and a short snippet. Paths inside containers use `!/`, for example `invoice.zip!/invoice.pdf.lnk`.

**Finding**
: One detected issue, with a rule ID (`GAL-AUTOEXEC-001`), a severity, a title, an ATT&CK ID and evidence.

**Hard trigger**
: A finding so strong (any critical severity) that it makes the verdict MALICIOUS on its own, whatever the score.

**IOC (Indicator of Compromise)**
: A concrete clue that something is malicious or talks to an attacker: a URL, domain, IP address or email address. Galahad lists every IOC it finds and flags risky ones, such as Discord webhooks, paste sites or raw IP URLs.

**Packer**
: A tool that compresses or encrypts an executable to hide its real code. Legitimate software uses packers too, so this is a signal, not proof.

**Risk score**
: 0–100, the sum of finding weights (critical 100, high 35, medium 15, low 5), with each rule counted once.

**Rule ID**
: The stable name of a detection, in the form `GAL-<AREA>-<NNN>`, for example `GAL-IOC-002`.

**Sinkhole**
: A fake destination that receives malicious traffic so it can be observed safely. Test fixtures use `*.sinkhole.test` domains, which can never resolve on the real internet.

**Static analysis**
: Inspecting files without running them: parsing configs, scripts, PDFs, Office documents and binaries. This is M1.

**Verdict**
: The overall result. `clean` (exit code 0), `suspicious` (10) or `malicious` (20). `clean` means no malicious indicators were found, not a guarantee of safety.

## Isolation

**Container**
: An isolated process that shares the host's kernel (Docker, Podman). Galahad does not treat a container as a safe boundary for malware, because a kernel exploit escapes it.

**Firecracker / Virtualization.framework / Hyper-V**
: The hypervisors Galahad uses on Linux, macOS and Windows to run guest VMs.

**Guest / host**
: The **host** is your real machine. The **guest** is the throwaway VM where untrusted files are opened. Only validated JSON results travel from guest to host.

**Honeytoken**
: A fake secret (a fake AWS key, a fake SSH key, a fake `.env`) planted in the guest VM. If a sample reads it and sends it out, that proves exfiltration. Planned for M4.

**Sandbox**
: Any isolated environment for running or inspecting untrusted things. In Galahad, the sandbox is a VM.

**`--unsafe-host`**
: A flag that makes `galahad-agent analyze` run on your real machine instead of a VM. Galahad refuses without it. Use it only for the bundled test fixtures; you accept the risk.

**VM (virtual machine)**
: A full simulated computer with its own kernel, separated from the host by a hypervisor. It is a much stronger boundary than a container.

**vsock**
: A private host-to-guest socket that does not use any network. Galahad's guest has no network card, so vsock is its only channel to the host.

## File formats

**CFB / OLE**
: Compound File Binary, the container format of old Office files (`.doc`, `.xls`) and of the macro storage inside new ones (`vbaProject.bin`).

**EICAR**
: A harmless, industry-standard test string that every antivirus detects on purpose. Galahad uses it to prove detection works. The repository never stores it whole; tests build it at run time.

**ELF / PE / Mach-O**
: Executable formats on Linux, Windows and macOS.

**JSONC**
: JSON with comments and trailing commas, used by VS Code settings and tasks files.

**OOXML**
: The modern Office formats (`.docx`, `.xlsx`, `.pptx`), which are zip archives of XML files.

## Project and process

**Benign twin**
: For each malicious test fixture there is a harmless look-alike that must come out `clean`. This catches false alarms.

**Black-box test**
: A test that uses only the public surface: exported Go API (`package <name>_test`) or the built binary run as a user would.

**Fixture / corpus**
: Sample inputs used by tests, under `testdata/corpus/`. Malicious-looking fixtures are harmless imitations: fake keys, `.test` domains and no real malware.

**Gate (quality gate)**
: `make gate`: format, vet, lint, cross-build, vulnerability scan, security scan, tests with the race detector, dependency allowlist and acceptance smoke tests. Every PR must pass it.

**P1–P10**
: The ten real-world problems Galahad must solve, listed in `docs/plan.md`. For example, P1 is the VS Code folder-open attack and P7 is "no false alarms". Acceptance tests are traced to them.

**Provenance attestation**
: A signed, verifiable record that a release file was built by this repository's GitHub workflow from a specific commit. Check it with `gh attestation verify`.
