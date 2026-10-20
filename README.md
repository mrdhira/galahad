# Galahad

Galahad inspects untrusted files, links and Git repositories inside an isolated VM before they touch your machine.

It targets the fake-recruiter attacks that ship a "take-home" repo, PDF or archive which runs code when you open it in VS Code, run `npm install`, or start the app.

> Status: early development. Do not rely on it yet.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/mrdhira/galahad/releases), then verify it with `sha256sum -c checksums.txt` and `gh attestation verify <file> --repo mrdhira/galahad`.

## Build

```sh
go build -o bin/galahad ./cmd/galahad
bin/galahad version
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
