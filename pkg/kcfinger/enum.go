package kcfinger

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// RealmInfo is the public, pre-auth information gathered for one realm.
type RealmInfo struct {
	Realm          string            `json:"realm"`
	Exists         bool              `json:"exists"`
	DisplayName    string            `json:"displayName,omitempty"`
	PublicKeyHead  string            `json:"realmPublicKeyHead,omitempty"`
	TokenService   string            `json:"tokenService,omitempty"`
	AccountService string            `json:"accountService,omitempty"`
	Issuer         string            `json:"issuer,omitempty"`
	Endpoints      map[string]string `json:"endpoints,omitempty"`
	GrantTypes     []string          `json:"grantTypesSupported,omitempty"`
	Scopes         []string          `json:"scopesSupported,omitempty"`
	IDTokenAlgs    []string          `json:"idTokenSigningAlgs,omitempty"`
	JWKS           []KeyInfo         `json:"jwks,omitempty"`
	SAMLNameIDs    []string          `json:"samlNameIDFormats,omitempty"`
	SAMLSsoURL     string            `json:"samlSingleSignOnService,omitempty"`
	Registration   bool              `json:"registrationAllowed"`
	PasswordReset  bool              `json:"resetPasswordAllowed"`
}

// KeyInfo is a summary of one JWKS key.
type KeyInfo struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// DefaultRealmWordlist is a small set of realm names commonly present.
var DefaultRealmWordlist = []string{
	"master", "account", "admin", "demo", "dev", "test", "staging", "prod",
	"production", "internal", "external", "users", "customers", "employees",
	"sso", "auth", "idp", "company", "corp", "main", "default",
}

var (
	reNameIDFormat = regexp.MustCompile(`(?i)<(?:[a-z0-9]+:)?NameIDFormat>\s*([^<\s]+)\s*</`)
	reSAMLSSO      = regexp.MustCompile(`(?i)SingleSignOnService[^>]*Location="([^"]+)"`)
)

// EnumerateRealm gathers public info for a single realm.
func (f *Fingerprinter) EnumerateRealm(ctx context.Context, kcRoot, realm string) RealmInfo {
	info := RealmInfo{Realm: realm, Endpoints: map[string]string{}}

	// 1. /realms/<realm> — public realm representation.
	if body, _, code, err := f.getBody(ctx, kcRoot+"/realms/"+realm); err == nil && code == 200 {
		var r struct {
			Realm          string `json:"realm"`
			PublicKey      string `json:"public_key"`
			TokenService   string `json:"token-service"`
			AccountService string `json:"account-service"`
		}
		if json.Unmarshal(body, &r) == nil && r.Realm != "" {
			info.Exists = true
			info.DisplayName = r.Realm
			info.PublicKeyHead = head(r.PublicKey, 40)
			info.TokenService = r.TokenService
			info.AccountService = r.AccountService
		}
	}

	// 2. OIDC discovery.
	if body, _, code, err := f.getBody(ctx, kcRoot+"/realms/"+realm+"/.well-known/openid-configuration"); err == nil && code == 200 {
		var d map[string]json.RawMessage
		if json.Unmarshal(body, &d) == nil {
			info.Exists = true
			info.Issuer = jstr(d["issuer"])
			for _, ep := range []string{
				"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
				"jwks_uri", "end_session_endpoint", "registration_endpoint",
				"introspection_endpoint", "revocation_endpoint",
				"device_authorization_endpoint", "backchannel_authentication_endpoint",
				"pushed_authorization_request_endpoint",
			} {
				if v := jstr(d[ep]); v != "" {
					info.Endpoints[ep] = v
				}
			}
			info.GrantTypes = jarr(d["grant_types_supported"])
			info.Scopes = jarr(d["scopes_supported"])
			info.IDTokenAlgs = jarr(d["id_token_signing_alg_values_supported"])
		}
	}

	// 3. JWKS.
	if body, _, code, err := f.getBody(ctx, kcRoot+"/realms/"+realm+"/protocol/openid-connect/certs"); err == nil && code == 200 {
		var j struct {
			Keys []KeyInfo `json:"keys"`
		}
		if json.Unmarshal(body, &j) == nil {
			info.JWKS = j.Keys
		}
	}

	// 4. SAML descriptor (NameID formats, SSO endpoint, public — IdP metadata).
	if body, _, code, err := f.getBody(ctx, kcRoot+"/realms/"+realm+"/protocol/saml/descriptor"); err == nil && code == 200 {
		set := map[string]bool{}
		for _, m := range reNameIDFormat.FindAllStringSubmatch(string(body), -1) {
			set[m[1]] = true
		}
		for k := range set {
			info.SAMLNameIDs = append(info.SAMLNameIDs, k)
		}
		sort.Strings(info.SAMLNameIDs)
		if m := reSAMLSSO.FindSubmatch(body); m != nil {
			info.SAMLSsoURL = string(m[1])
		}
	}

	// 5. Self-service flags from the login page (register / reset-password links).
	if info.Exists {
		if body, _, code, err := f.getBody(ctx, kcRoot+"/realms/"+realm+"/protocol/openid-connect/auth?client_id=account&response_type=code&scope=openid&redirect_uri=http://localhost"); err == nil && code == 200 {
			s := string(body)
			info.Registration = strings.Contains(s, "/registrations?") || strings.Contains(s, "kc-registration")
			info.PasswordReset = strings.Contains(s, "/login-actions/reset-credentials") || strings.Contains(s, "kc-reset")
		}
	}

	return info
}

// Enumerate probes the realm parsed from the URL plus a wordlist; returns the
// realms that exist. If extra is non-empty it replaces the default wordlist.
func (f *Fingerprinter) Enumerate(ctx context.Context, rawURL string, extra []string) ([]RealmInfo, error) {
	base, err := normalizeBase(rawURL)
	if err != nil {
		return nil, err
	}
	kcRoot, realm := deriveRoot(base)

	names := []string{realm}
	wl := DefaultRealmWordlist
	if len(extra) > 0 {
		wl = extra
	}
	seen := map[string]bool{realm: true}
	for _, n := range wl {
		if !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}

	var out []RealmInfo
	for _, n := range names {
		if info := f.EnumerateRealm(ctx, kcRoot, n); info.Exists {
			out = append(out, info)
		}
	}
	return out, nil
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func jstr(r json.RawMessage) string {
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	return ""
}

func jarr(r json.RawMessage) []string {
	var a []string
	json.Unmarshal(r, &a)
	return a
}
