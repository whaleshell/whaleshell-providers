// Package provider defines reusable provider profiles (catalog) and composition
// into sandbox effective policy (OpenShell-style level C).
package provider

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/whaleshell/whaleshell-core/policy"
	"gopkg.in/yaml.v3"
)

// Profile is a reusable provider type (catalog entry).
type Profile struct {
	ID               string             `yaml:"id" json:"id"`
	ResourceVersion  uint64             `yaml:"resource_version,omitempty" json:"resource_version,omitempty"`
	Annotations      map[string]string  `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	DisplayName      string             `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Description      string             `yaml:"description,omitempty" json:"description,omitempty"`
	Category         string             `yaml:"category,omitempty" json:"category,omitempty"`
	InferenceCapable bool               `yaml:"inference_capable,omitempty" json:"inference_capable,omitempty"`
	Discovery        Discovery          `yaml:"discovery,omitempty" json:"discovery,omitempty"`
	Endpoints        []policy.AllowRule `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries         []string           `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	Credentials      []Credential       `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Discovery selects credentials considered by --from-existing. An empty list
// retains whaleshell's historical behavior and discovers all profile credentials.
type Discovery struct {
	Credentials []string `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Credential declares env keys for an attached instance.
// Values live in the gateway secret store; guests see whaleshell:resolve:env:KEY
// placeholders unless InjectEnv is false (sidecar-only — Cursor OAuth path).
type Credential struct {
	Name         string             `yaml:"name" json:"name"`
	Description  string             `yaml:"description,omitempty" json:"description,omitempty"`
	EnvVars      []string           `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	AuthStyle    string             `yaml:"auth_style,omitempty" json:"auth_style,omitempty"`
	Header       string             `yaml:"header_name,omitempty" json:"header_name,omitempty"`
	QueryParam   string             `yaml:"query_param,omitempty" json:"query_param,omitempty"`
	PathTemplate string             `yaml:"path_template,omitempty" json:"path_template,omitempty"`
	Required     bool               `yaml:"required,omitempty" json:"required,omitempty"`
	Secret       bool               `yaml:"secret,omitempty" json:"secret,omitempty"`
	Refresh      *CredentialRefresh `yaml:"refresh,omitempty" json:"refresh,omitempty"`
	TokenGrant   *TokenGrant        `yaml:"token_grant,omitempty" json:"token_grant,omitempty"`
	// InjectEnv controls guest env placeholders. nil/omitted → true.
	// Set false for agents that client-validate API keys (e.g. Cursor Agent).
	InjectEnv *bool `yaml:"inject_env,omitempty" json:"inject_env,omitempty"`
}

// CredentialRefresh describes gateway-side rotation inputs. The gateway may
// reject strategies it cannot execute, but import/export retains the contract.
type CredentialRefresh struct {
	Strategy             string            `yaml:"strategy" json:"strategy"`
	TokenURL             string            `yaml:"token_url,omitempty" json:"token_url,omitempty"`
	TokenURI             string            `yaml:"token_uri,omitempty" json:"token_uri,omitempty"`
	Scopes               []string          `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	RefreshBefore        string            `yaml:"refresh_before,omitempty" json:"refresh_before,omitempty"`
	MaxLifetime          string            `yaml:"max_lifetime,omitempty" json:"max_lifetime,omitempty"`
	RefreshBeforeSeconds int64             `yaml:"refresh_before_seconds,omitempty" json:"refresh_before_seconds,omitempty"`
	MaxLifetimeSeconds   int64             `yaml:"max_lifetime_seconds,omitempty" json:"max_lifetime_seconds,omitempty"`
	Material             []RefreshMaterial `yaml:"material,omitempty" json:"material,omitempty"`
	AdditionalOutputs    []RefreshOutput   `yaml:"additional_outputs,omitempty" json:"additional_outputs,omitempty"`
}

type RefreshOutput struct {
	Output     string `yaml:"output" json:"output"`
	Credential string `yaml:"credential" json:"credential"`
}

type RefreshMaterial struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Secret      *bool  `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// TokenGrant describes an optional workload-identity OAuth token exchange.
type TokenGrant struct {
	GrantType           string                       `yaml:"grant_type" json:"grant_type"`
	TokenEndpoint       string                       `yaml:"token_endpoint" json:"token_endpoint"`
	Audience            string                       `yaml:"audience,omitempty" json:"audience,omitempty"`
	JWTSVIDAudience     string                       `yaml:"jwt_svid_audience,omitempty" json:"jwt_svid_audience,omitempty"`
	ClientAssertionType string                       `yaml:"client_assertion_type,omitempty" json:"client_assertion_type,omitempty"`
	Scopes              []string                     `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	CacheTTL            string                       `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`
	RequestedTokenType  string                       `yaml:"requested_token_type,omitempty" json:"requested_token_type,omitempty"`
	SubjectToken        *SubjectToken                `yaml:"subject_token,omitempty" json:"subject_token,omitempty"`
	AudienceOverrides   []TokenGrantAudienceOverride `yaml:"audience_overrides,omitempty" json:"audience_overrides,omitempty"`
}

type SubjectToken struct {
	Source           string `yaml:"source" json:"source"`
	Credential       string `yaml:"credential,omitempty" json:"credential,omitempty"`
	SubjectTokenType string `yaml:"subject_token_type,omitempty" json:"subject_token_type,omitempty"`
}

type TokenGrantAudienceOverride struct {
	Host     string   `yaml:"host" json:"host"`
	Port     int      `yaml:"port" json:"port"`
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	Audience string   `yaml:"audience,omitempty" json:"audience,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// Instance is a named provider on a gateway (env key refs only, no secret values).
type Instance struct {
	Name    string   `yaml:"name" json:"name"`
	Type    string   `yaml:"type" json:"type"` // profile id
	EnvVars []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
}

// Validate checks a profile document.
func (p Profile) Validate() error {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return fmt.Errorf("provider profile: id required")
	}
	if !validProfileID(id) {
		return fmt.Errorf("provider profile %q: id must contain lowercase letters, digits, and hyphens", id)
	}
	category := strings.TrimSpace(p.Category)
	switch category {
	case "", "other", "agent", "inference", "source_control", "messaging", "data", "knowledge":
	default:
		return fmt.Errorf("provider profile %q: unsupported category %q", id, category)
	}
	credentials := map[string]Credential{}
	for i, ep := range p.Endpoints {
		if err := policy.ValidateAllowRule(fmt.Sprintf("endpoints[%d]", i), ep); err != nil {
			return fmt.Errorf("provider profile %q: %w", id, err)
		}
	}
	for i, c := range p.Credentials {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("provider profile %q: credentials[%d]: name required", id, i)
		}
		if len(c.EnvVars) == 0 && c.Refresh == nil && c.TokenGrant == nil {
			return fmt.Errorf("provider profile %q: credentials[%d]: env_vars required", id, i)
		}
		if _, exists := credentials[name]; exists {
			return fmt.Errorf("provider profile %q: duplicate credential %q", id, name)
		}
		credentials[name] = c
		if c.AuthStyle != "" && c.AuthStyle != "basic" && c.AuthStyle != "bearer" && c.AuthStyle != "header" && c.AuthStyle != "query" && c.AuthStyle != "path" {
			return fmt.Errorf("provider profile %q: credentials[%d].auth_style %q is unsupported (supported: basic, bearer, header, query, path)", id, i, c.AuthStyle)
		}
		if c.AuthStyle == "header" && strings.TrimSpace(c.Header) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].header_name is required for auth_style header", id, i)
		}
		if c.AuthStyle == "query" && strings.TrimSpace(c.QueryParam) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].query_param is required for auth_style query", id, i)
		}
		if c.AuthStyle == "path" && strings.TrimSpace(c.PathTemplate) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].path_template is required for auth_style path", id, i)
		}
		if c.Refresh != nil {
			if c.Refresh.RefreshBeforeSeconds < 0 || c.Refresh.MaxLifetimeSeconds < 0 {
				return fmt.Errorf("provider profile %q: credentials[%d].refresh lifetimes must be non-negative", id, i)
			}
			switch c.Refresh.Strategy {
			case "static", "external", "oauth2_refresh_token", "oauth2_client_credentials", "google_service_account_jwt", "aws_sts_assume_role":
			default:
				return fmt.Errorf("provider profile %q: credentials[%d].refresh.strategy %q is unsupported", id, i, c.Refresh.Strategy)
			}
			if c.Refresh.TokenURL != "" {
				if err := validateTokenEndpoint(c.Refresh.TokenURL); err != nil {
					return fmt.Errorf("provider profile %q: credentials[%d].refresh.token_url: %w", id, i, err)
				}
			}
		}
		if c.TokenGrant != nil {
			if c.TokenGrant.GrantType != "client_credentials" && c.TokenGrant.GrantType != "token_exchange" && c.TokenGrant.GrantType != "ClientCredentials" && c.TokenGrant.GrantType != "TokenExchange" {
				return fmt.Errorf("provider profile %q: credentials[%d].token_grant.grant_type %q is unsupported", id, i, c.TokenGrant.GrantType)
			}
			if err := validateTokenEndpoint(c.TokenGrant.TokenEndpoint); err != nil {
				return fmt.Errorf("provider profile %q: credentials[%d].token_grant.token_endpoint: %w", id, i, err)
			}
		}
	}
	if len(p.Discovery.Credentials) > 0 {
		seen := map[string]struct{}{}
		for _, name := range p.Discovery.Credentials {
			name = strings.TrimSpace(name)
			if _, ok := credentials[name]; !ok {
				return fmt.Errorf("provider profile %q: discovery references unknown credential %q", id, name)
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("provider profile %q: duplicate discovery credential %q", id, name)
			}
			seen[name] = struct{}{}
		}
	}
	return nil
}

func validateTokenEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("must be an absolute URL with a host")
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("must not contain user information or a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local")) {
		return nil
	}
	return fmt.Errorf("must use HTTPS (HTTP is allowed only for loopback or Kubernetes service DNS)")
}

// ValidateRuntime rejects accepted schema features that whaleshell cannot execute
// so import/export compatibility never implies a working credential flow.
func (p Profile) ValidateRuntime() error {
	for i, credential := range p.Credentials {
		if credential.TokenGrant != nil {
			return fmt.Errorf("provider profile %q: credentials[%d].token_grant is not supported by whaleshell runtime", p.ID, i)
		}
		if credential.Refresh == nil {
			continue
		}
		switch credential.Refresh.Strategy {
		case "oauth2_refresh_token", "oauth2_client_credentials", "oauth2-refresh-token", "oauth2-client-credentials":
			if strings.TrimSpace(credential.Refresh.TokenURL) == "" {
				return fmt.Errorf("provider profile %q: credentials[%d].refresh.token_url is required by whaleshell runtime", p.ID, i)
			}
		default:
			return fmt.Errorf("provider profile %q: credentials[%d].refresh.strategy %q is not supported by whaleshell runtime", p.ID, i, credential.Refresh.Strategy)
		}
	}
	for i, endpoint := range p.Endpoints {
		if endpoint.CredentialSigning != "" {
			return fmt.Errorf("provider profile %q: endpoints[%d].credential_signing is not supported by whaleshell runtime", p.ID, i)
		}
	}
	return nil
}

func validProfileID(id string) bool {
	if id == "" || id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// ParseYAML loads a profile from bytes.
func ParseYAML(b []byte) (Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("provider profile: parse: %w", err)
	}
	// OpenShell omits TLS handling on L7 HTTPS endpoints and defaults them to
	// inspection. Apply that default before whaleshell policy validation.
	for i := range p.Endpoints {
		if p.Endpoints[i].TLS == "" && p.Endpoints[i].Protocol != "" && p.Endpoints[i].Port == 443 {
			p.Endpoints[i].TLS = "terminate"
		}
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// LoadFile reads a profile YAML file.
func LoadFile(path string) (Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	return ParseYAML(b)
}

// LoadDir loads all *.yaml/*.yml profiles from a directory (non-recursive).
func LoadDir(dir string) (map[string]Profile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]Profile{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if _, exists := out[p.ID]; exists {
			return nil, fmt.Errorf("provider profile %q: duplicate ID in %s", p.ID, dir)
		}
		out[p.ID] = p
	}
	return out, nil
}

// EnvKeys returns all credential env var names from the profile.
func (p Profile) EnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

// DiscoveryCredentials returns the selected credential definitions in profile order.
func (p Profile) DiscoveryCredentials() []Credential {
	if len(p.Discovery.Credentials) == 0 {
		return append([]Credential(nil), p.Credentials...)
	}
	byName := make(map[string]Credential, len(p.Credentials))
	for _, credential := range p.Credentials {
		byName[credential.Name] = credential
	}
	out := make([]Credential, 0, len(p.Discovery.Credentials))
	for _, name := range p.Discovery.Credentials {
		if credential, ok := byName[name]; ok {
			out = append(out, credential)
		}
	}
	return out
}

// GuestEnvKeys returns credential env keys that should be injected into the guest
// as whaleshell:resolve:env placeholders (excludes inject_env: false).
func (p Profile) GuestEnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		if c.InjectEnv != nil && !*c.InjectEnv {
			continue
		}
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

// DiscoverEnvVars picks host env keys for a provider instance (OpenShell --from-existing).
// For each credential, the first non-empty env_vars entry wins. Required credentials
// with no value on the host return an error. Values are never returned — only key names.
func (p Profile) DiscoverEnvVars() ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.DiscoveryCredentials() {
		found := ""
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
				// Host may leak guest placeholders into the process env — treat as missing.
				if strings.HasPrefix(strings.TrimSpace(v), "whaleshell:resolve:env:") ||
					strings.HasPrefix(strings.TrimSpace(v), "openshell:resolve:env:") {
					continue
				}
				found = k
				break
			}
		}
		if found == "" {
			if c.Required {
				want := strings.Join(c.EnvVars, "|")
				return nil, fmt.Errorf("provider %q: credential %q missing on host (export %s)", p.ID, c.Name, want)
			}
			continue
		}
		if _, ok := seen[found]; ok {
			continue
		}
		seen[found] = struct{}{}
		out = append(out, found)
	}
	if len(out) == 0 && len(p.Credentials) > 0 {
		return nil, fmt.Errorf("provider %q: no credential env vars found on host", p.ID)
	}
	return out, nil
}

// Layer is one attached provider contribution.
type Layer struct {
	InstanceName string
	Profile      Profile
	EnvVars      []string // instance override; empty → profile defaults
}

// OmitProviderComposed removes network_policies rules whose id is prefixed with
// "provider." (stamped by EffectivePolicy). Use when accepting a policy set that may have
// been edited from `policy get --full` so provider-composed entries are not duplicated
// into the durable base (OpenShell: edit --base, not --full).
func OmitProviderComposed(doc policy.Document) (policy.Document, int) {
	allows := doc.NetworkAllows()
	if len(allows) == 0 {
		return doc, 0
	}
	kept := make([]policy.AllowRule, 0, len(allows))
	n := 0
	for _, r := range allows {
		id := strings.TrimSpace(r.ID)
		if strings.HasPrefix(id, "provider.") {
			n++
			continue
		}
		kept = append(kept, r)
	}
	if n == 0 {
		return doc, 0
	}
	out := doc
	out.SetNetworkAllows(kept)
	return out, n
}

// EffectivePolicy is the OpenShell composition step: effective policy =
// base + provider-composed profile entries (unless suppressProviders).
func EffectivePolicy(base policy.Document, layers []Layer, suppressProviders bool) policy.Document {
	out := base
	allows := append([]policy.AllowRule{}, out.NetworkAllows()...)
	if out.Credentials == nil {
		out.Credentials = &policy.Credentials{}
	} else {
		credCopy := *out.Credentials
		credCopy.EnvAllow = append([]string{}, out.Credentials.EnvAllow...)
		out.Credentials = &credCopy
	}
	if suppressProviders {
		out.SetNetworkAllows(allows)
		return out
	}
	envSeen := map[string]struct{}{}
	for _, k := range out.Credentials.EnvAllow {
		envSeen[k] = struct{}{}
	}
	for _, layer := range layers {
		p := layer.Profile
		keys := layer.EnvVars
		if len(keys) == 0 {
			keys = p.EnvKeys()
		}
		guestKeys := p.GuestEnvKeys()
		if len(layer.EnvVars) > 0 {
			// Instance override: still honor profile inject_env:false exclusions.
			omit := map[string]struct{}{}
			for _, c := range p.Credentials {
				if c.InjectEnv != nil && !*c.InjectEnv {
					for _, k := range c.EnvVars {
						omit[strings.TrimSpace(k)] = struct{}{}
					}
				}
			}
			guestKeys = nil
			for _, k := range keys {
				if _, skip := omit[k]; skip {
					continue
				}
				guestKeys = append(guestKeys, k)
			}
		}
		for i, ep := range p.Endpoints {
			rule := ep
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("provider.%s.%d", layer.InstanceName, i)
			} else {
				rule.ID = fmt.Sprintf("provider.%s.%s", layer.InstanceName, rule.ID)
			}
			if len(rule.Binaries) == 0 && len(p.Binaries) > 0 {
				rule.Binaries = append([]string{}, p.Binaries...)
			}
			rule.CredentialKeys = append([]string{}, keys...)
			allows = append(allows, rule)
		}
		for _, k := range guestKeys {
			if _, ok := envSeen[k]; ok {
				continue
			}
			envSeen[k] = struct{}{}
			out.Credentials.EnvAllow = append(out.Credentials.EnvAllow, k)
		}
	}
	out.SetNetworkAllows(allows)
	return out
}

// FindBuiltinDir locates a providers catalog directory (cwd or next to the executable).
func FindBuiltinDir() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "whaleshell-providers", "profiles"),
			filepath.Join(wd, "whaleshell-cli", "providers"),
			filepath.Join(wd, "providers"),
			filepath.Join(wd, "profiles"),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "profiles"),
			filepath.Join(dir, "providers"),
			filepath.Join(dir, "..", "profiles"),
			filepath.Join(dir, "..", "providers"),
			filepath.Join(dir, "..", "whaleshell-providers", "profiles"),
			filepath.Join(dir, "..", "whaleshell-cli", "providers"),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}
