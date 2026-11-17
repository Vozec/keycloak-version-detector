package kcfinger

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewHTTPClient returns an HTTP client configured for direct connections or
// for an explicit HTTP(S) / SOCKS5 proxy. Proxy credentials may be supplied in
// the URL, for example http://user:pass@127.0.0.1:8080.
func NewHTTPClient(rawProxy string, insecure bool, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // controlled by the explicit -k option
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 32,
	}

	if strings.TrimSpace(rawProxy) != "" {
		proxyURL, err := parseProxyURL(rawProxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

func parseProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5, or socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing host", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("invalid proxy URL %q: paths are not supported", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid proxy URL %q: query strings and fragments are not supported", raw)
	}
	u.Path = ""
	return u, nil
}
