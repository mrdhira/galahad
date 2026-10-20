# Galahad

Galahad inspects untrusted files, links and Git repositories inside an isolated VM before they touch your machine.

It targets the fake-recruiter attacks that ship a "take-home" repo, PDF or archive which runs code when you open it in VS Code, run `npm install`, or start the app.

> Status: early development. Do not rely on it yet.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/mrdhira/galahad/releases), then verify it with `sha256sum --ignore-missing -c checksums.txt` (macOS: `shasum -a 256 --ignore-missing -c checksums.txt`) and `gh attestation verify <file> --repo mrdhira/galahad`.

## Development

```sh
make tools   # install golangci-lint, gosec, govulncheck at pinned versions
make build   # build bin/galahad
make gate    # run the full quality gate
```

Set `SKIP_VULN=1` for `make gate` only where vuln.go.dev is unreachable.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
