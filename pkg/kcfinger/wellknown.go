package kcfinger

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
)

// WellKnownMarker is an OIDC discovery field whose presence implies a minimum
// Keycloak version (the release that introduced it). This complements asset
// hashing: it works even when the theme is identical across versions and when
// the resourceVersion is hidden, because it reflects server *behaviour*.
//
// Versions are the release that first advertised the field in
// /.well-known/openid-configuration. They are conservative; refine with
// `kcfinger`'s source-derived data if needed. Treat them as a floor.
type WellKnownMarker struct {
	Field      string
	MinVersion string
	Label      string
}

// WellKnownMarkers — field -> release that first advertised it, auto-derived by
// diffing OIDCConfigurationRepresentation.java across all tags (not guessed).
// The newest field present on a target sets a version floor. Regenerate with
// `kcvf builddb wellknown`. Only fields newer than the 12.x baseline are listed
// (older fields give a useless "floor >= 12").
var WellKnownMarkers = []WellKnownMarker{
	{Field: "require_request_uri_registration", MinVersion: "12.0.2", Label: "require_request_uri_registration"},
	{Field: "device_authorization_endpoint", MinVersion: "13.0.0", Label: "Device Flow"},
	{Field: "backchannel_authentication_endpoint", MinVersion: "13.0.0", Label: "CIBA"},
	{Field: "backchannel_token_delivery_modes_supported", MinVersion: "13.0.0", Label: "CIBA delivery modes"},
	{Field: "introspection_endpoint_auth_methods_supported", MinVersion: "13.0.0", Label: "introspection auth methods"},
	{Field: "introspection_endpoint_auth_signing_alg_values_supported", MinVersion: "13.0.0", Label: "introspection auth signing"},
	{Field: "pushed_authorization_request_endpoint", MinVersion: "15.0.0", Label: "PAR (RFC 9126)"},
	{Field: "require_pushed_authorization_requests", MinVersion: "15.0.0", Label: "PAR enforced flag"},
	{Field: "mtls_endpoint_aliases", MinVersion: "15.0.0", Label: "mTLS endpoint aliases"},
	{Field: "authorization_signing_alg_values_supported", MinVersion: "15.0.0", Label: "JARM signing"},
	{Field: "authorization_encryption_alg_values_supported", MinVersion: "15.0.0", Label: "JARM encryption"},
	{Field: "request_object_encryption_alg_values_supported", MinVersion: "15.0.0", Label: "request object encryption"},
	{Field: "backchannel_authentication_request_signing_alg_values_supported", MinVersion: "15.0.0", Label: "CIBA request signing"},
	{Field: "frontchannel_logout_supported", MinVersion: "15.1.0", Label: "front-channel logout"},
	{Field: "frontchannel_logout_session_supported", MinVersion: "15.1.0", Label: "front-channel logout session"},
	{Field: "acr_values_supported", MinVersion: "17.0.0", Label: "acr_values_supported"},
	{Field: "userinfo_encryption_alg_values_supported", MinVersion: "18.0.0", Label: "userinfo encryption"},
	{Field: "authorization_response_iss_parameter_supported", MinVersion: "23.0.0", Label: "iss response param (RFC 9207)"},
	{Field: "dpop_signing_alg_values_supported", MinVersion: "23.0.0", Label: "DPoP (RFC 9449)"},
	{Field: "prompt_values_supported", MinVersion: "26.1.0", Label: "prompt_values_supported"},
}

var reRealmInPath = regexp.MustCompile(`/realms/([^/?#]+)`)

// MarkerHit is a discovery field found on the target with its intro version.
type MarkerHit struct {
	Label      string `json:"label"`
	Field      string `json:"field"`
	MinVersion string `json:"minVersion"`
}

// discoveryDocs are the pre-auth metadata documents we probe, in order. Their
// fields are largely shared, so any one reached yields a version floor — robust
// when one is disabled but another is exposed.
var discoveryDocs = []string{
	".well-known/openid-configuration",
	".well-known/oauth-authorization-server",
	".well-known/uma2-configuration",
}

// WellKnownResult holds the floor inferred from OIDC discovery.
type WellKnownResult struct {
	Realm      string      `json:"realm"`
	Reached    bool        `json:"reached"`
	Docs       []string    `json:"docs,omitempty"` // discovery docs that responded
	Present    []MarkerHit `json:"present"`        // markers found, with intro version
	MinVersion string      `json:"minVersion"`
}

// PresentLabels returns just the labels (newest-version first).
func (w WellKnownResult) PresentLabels() []string {
	out := make([]string, len(w.Present))
	for i, p := range w.Present {
		out[i] = p.Label
	}
	return out
}

// probeWellKnown fetches /realms/<realm>/.well-known/openid-configuration and
// returns the version floor implied by the fields present.
func (f *Fingerprinter) probeWellKnown(ctx context.Context, base, realm string) WellKnownResult {
	out := WellKnownResult{Realm: realm}
	markers := WellKnownMarkers
	if len(f.DB.WellKnown) > 0 {
		markers = f.DB.WellKnown
	}
	// Union of fields seen across all reachable discovery documents.
	seenField := map[string]bool{}
	for _, doc := range discoveryDocs {
		body, _, code, err := f.getBody(ctx, base+"/realms/"+realm+"/"+doc)
		if err != nil || code != 200 {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		out.Reached = true
		out.Docs = append(out.Docs, doc)
		for k := range m {
			seenField[k] = true
		}
	}
	if !out.Reached {
		return out
	}
	for _, mk := range markers {
		if seenField[mk.Field] {
			out.Present = append(out.Present, MarkerHit{Label: mk.Label, Field: mk.Field, MinVersion: mk.MinVersion})
			if CompareVersions(mk.MinVersion, out.MinVersion) > 0 {
				out.MinVersion = mk.MinVersion
			}
		}
	}
	// newest intro version first
	sort.Slice(out.Present, func(i, j int) bool {
		return CompareVersions(out.Present[i].MinVersion, out.Present[j].MinVersion) > 0
	})
	return out
}
