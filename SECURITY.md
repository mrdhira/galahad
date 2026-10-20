# Security Policy

Galahad exists to handle hostile input safely, so security reports get priority over all other work.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No. Upgrade to the latest release. |

Before 1.0.0, only the latest `v0.x` release receives fixes.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: open the [Security tab](https://github.com/mrdhira/galahad/security) and choose **Report a vulnerability**. This creates a private advisory visible only to you and the maintainer.

Include:
- the Galahad version (`galahad version --json`) and host OS
- what you did, what you expected and what happened
- the smallest input that reproduces it, and its SHA-256

**Never attach live malware in plain form.** Share a hash, or attach it in a ZIP encrypted with the password `infected`, and say so in the report.

## What counts as a vulnerability

In scope, highest severity first:
1. **Sandbox escape:** a sample reads or writes host files, runs code on the host, or reaches the host or local network from inside a guest VM, or bypasses the egress proxy allowlist.
2. **Host-side parsing:** the host binary parses, executes or opens untrusted bytes, or crashes or hangs on them.
3. **Secret exposure:** host credentials or environment variables reach a guest VM or a report, or a key or host secret reaches a decision provider other than the one it belongs to, or appears in a prompt.
4. **Report injection:** sample content runs as script or active content when a report is opened.
5. **Verdict tampering:** a sample forces a clean verdict through a flaw in Galahad itself. Examples are prompt injection that bypasses the decision-provider cap, or crafted output that the host trusts without validating it.
6. **Supply chain:** release artifacts, checksums, provenance attestations or guest images that can be swapped or fail to verify.

Out of scope:
- A specific malware sample that Galahad does not detect, when no flaw lets it tamper with the analysis. Report detection gaps as a normal issue with the sample's hash.
- VM escapes in the hypervisor itself (Firecracker, Apple Virtualization.framework, Hyper-V). Report those to their vendors. Tell us too if Galahad's configuration makes them easier.
- Vulnerabilities in third-party tools inside the guest image that do not affect the host.
- Attacks that need an already-compromised host.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix or mitigation for sandbox escape and host-side issues | within 30 days |
| Fix for other issues | within 90 days |

You will hear about progress at least every 14 days. Fixes ship as a new release with a GitHub Security Advisory. With your permission, the advisory credits you.

## Safe harbor

Good-faith research that follows this policy is welcome. That means:
- testing only on systems you own
- not using real victims' data
- giving reasonable time for a fix before public disclosure

The maintainer will not pursue or support legal action against you for such research.
