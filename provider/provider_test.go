package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-core/policy"
	"gopkg.in/yaml.v3"
)

func TestParseGitHubProfile(t *testing.T) {
	const yaml = `
id: github
category: source_control
binaries: [/usr/bin/gh, /usr/bin/git]
credentials:
  - name: api_token
    env_vars: [GITHUB_TOKEN, GH_TOKEN]
    required: true
endpoints:
  - id: api
    host: api.github.com
    port: 443
    protocol: rest
    tls: terminate
    access: read-only
  - id: git
    host: github.com
    port: 443
    protocol: rest
    tls: terminate
    rules:
      - allow: { method: GET, path: "**" }
      - allow: { method: POST, path: "/**/git-upload-pack" }
`
	p, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "github" || len(p.Endpoints) != 2 {
		t.Fatalf("%+v", p)
	}
	keys := p.EnvKeys()
	if len(keys) != 2 || keys[0] != "GITHUB_TOKEN" || keys[1] != "GH_TOKEN" {
		t.Fatalf("keys=%v", keys)
	}
}

func TestOpenShellProviderProfileFixtures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "openshell"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		t.Run(strings.TrimSuffix(entry.Name(), ".yaml"), func(t *testing.T) {
			p, err := LoadFile(filepath.Join("testdata", "openshell", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if p.ID == "" {
				t.Fatal("upstream profile id lost")
			}
		})
	}
}

func TestOpenShellExtendedProfileFieldsRoundTrip(t *testing.T) {
	input := []byte(`id: custom
resource_version: 7
annotations: {source: "migration"}
credentials:
  - name: api_key
    env_vars: [CUSTOM_API_KEY]
    auth_style: query
    query_param: key
    refresh:
      strategy: oauth2_client_credentials
      token_url: https://auth.example/token
      refresh_before_seconds: 30
      additional_outputs:
        - {output: refresh_token, credential: refresh_token}
    token_grant:
      grant_type: client_credentials
      token_endpoint: https://auth.example/token
      audience_overrides:
        - {host: api.example, port: 443, path: /v1/**, audience: api://custom}
discovery:
  credentials: [api_key]
`)
	p, err := ParseYAML(input)
	if err != nil {
		t.Fatal(err)
	}
	if p.ResourceVersion != 7 || p.Annotations["source"] != "migration" || p.Credentials[0].Refresh.RefreshBeforeSeconds != 30 || p.Credentials[0].TokenGrant.AudienceOverrides[0].Audience != "api://custom" {
		t.Fatalf("OpenShell fields lost: %+v", p)
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseYAML(b); err != nil {
		t.Fatalf("marshaled profile did not parse: %v", err)
	}
}

func TestDiscoveryUsesNamedCredentialsOnly(t *testing.T) {
	p, err := LoadFile(filepath.Join("testdata", "openshell", "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range p.EnvKeys() {
		t.Setenv(key, "")
	}
	t.Setenv("CODEX_AUTH_ACCESS_TOKEN", "access")
	t.Setenv("CODEX_AUTH_REFRESH_TOKEN", "refresh")
	t.Setenv("CODEX_AUTH_ACCOUNT_ID", "account")
	keys, err := p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("optional id token should not block discovery: %v", keys)
	}
	t.Setenv("CODEX_AUTH_ID_TOKEN", "id")
	keys, err = p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("discovered keys=%v", keys)
	}
}

func TestProfileParserRejectsUnsupportedFields(t *testing.T) {
	profile := []byte("id: sample\nrefresh: {strategy: oauth2-refresh-token}\n")
	if _, err := ParseYAML(profile); err == nil || !strings.Contains(err.Error(), "field refresh not found") {
		t.Fatalf("expected precise unsupported-field error, got %v", err)
	}
}

func TestLoadDirRejectsDuplicateProfileIDs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("id: duplicate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate ID") {
		t.Fatalf("expected duplicate profile error, got %v", err)
	}
}

func TestDiscoverEnvVars(t *testing.T) {
	p := Profile{
		ID: "github",
		Credentials: []Credential{{
			Name: "api_token", EnvVars: []string{"GITHUB_TOKEN", "GH_TOKEN"}, Required: true,
		}},
	}
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "tok")
	keys, err := p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "GH_TOKEN" {
		t.Fatalf("%v", keys)
	}
	t.Setenv("GH_TOKEN", "")
	if _, err := p.DiscoverEnvVars(); err == nil {
		t.Fatal("expected missing credential error")
	}
}

func TestEffectivePolicy(t *testing.T) {
	base := policy.Document{Version: 1}
	p := Profile{
		ID: "nvidia",
		Endpoints: []policy.AllowRule{{
			Host: "integrate.api.nvidia.com", Port: 443,
			Protocol: "rest", TLS: "terminate", Access: "read-write",
		}},
		Binaries: []string{"/usr/bin/curl"},
		Credentials: []Credential{{
			Name: "api_key", EnvVars: []string{"NVIDIA_API_KEY"},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	out := EffectivePolicy(base, []Layer{{InstanceName: "nv", Profile: p}}, false)
	allows := out.NetworkAllows()
	if len(allows) != 1 {
		t.Fatalf("allow=%d", len(allows))
	}
	if allows[0].ID != "provider.nv.0" {
		t.Fatalf("id=%s", allows[0].ID)
	}
	if len(allows[0].Binaries) != 1 {
		t.Fatalf("binaries=%v", allows[0].Binaries)
	}
	if out.Credentials == nil || len(out.Credentials.EnvAllow) != 1 || out.Credentials.EnvAllow[0] != "NVIDIA_API_KEY" {
		t.Fatalf("env=%v", out.Credentials)
	}
	if len(base.NetworkAllows()) != 0 {
		t.Fatalf("base mutated: %d", len(base.NetworkAllows()))
	}
	fresh := policy.Document{Version: 1}
	suppressed := EffectivePolicy(fresh, []Layer{{InstanceName: "nv", Profile: p}}, true)
	if len(suppressed.NetworkAllows()) != 0 {
		t.Fatalf("expected suppress, got %d", len(suppressed.NetworkAllows()))
	}
}

func TestOmitProviderComposed(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{
		{ID: "github-push", Host: "github.com", Port: 443},
		{ID: "provider.gh.api", Host: "api.github.com", Port: 443},
		{ID: "provider.gh.git", Host: "github.com", Port: 443},
	})
	out, n := OmitProviderComposed(doc)
	if n != 2 {
		t.Fatalf("stripped=%d", n)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 || allows[0].ID != "github-push" {
		t.Fatalf("%+v", allows)
	}
	if len(doc.NetworkAllows()) != 3 {
		t.Fatalf("input mutated")
	}
	p := Profile{
		ID: "github",
		Endpoints: []policy.AllowRule{
			{ID: "api", Host: "api.github.com", Port: 443, Protocol: "rest", TLS: "terminate", Access: "read-only"},
		},
		Credentials: []Credential{{Name: "t", EnvVars: []string{"GITHUB_TOKEN"}}},
	}
	eff := EffectivePolicy(out, []Layer{{InstanceName: "gh", Profile: p}}, false)
	if len(eff.NetworkAllows()) != 2 {
		t.Fatalf("effective allow=%d %+v", len(eff.NetworkAllows()), eff.NetworkAllows())
	}
}

func TestAuditMatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 443, Protocol: "rest", TLS: "terminate",
		Access: "read-only", Enforcement: "audit",
	}
	ok, _ := rule.MatchHTTP("POST", "/v1")
	if ok {
		t.Fatal("POST should fail MatchHTTP on read-only")
	}
	if !rule.IsAudit() {
		t.Fatal("expected audit")
	}
}
