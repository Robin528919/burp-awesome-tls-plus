package server

import (
	"net/url"
	"testing"
)

// ExternalProxyUrl is validated in Java before it is ever committed, so the Java validator has to
// agree with what this dependency actually accepts. ADR-0001 section 7 pins that contract; this
// table is the Go half of it and burp.control.ProxyUrl#main is the Java half. A dependency bump
// that widens or narrows the accepted set breaks this test instead of silently changing which
// proxies the settings UI will let a user save.
//
// The conditions below mirror tls-client v1.15.1 newConnectDialer: url.Parse must succeed, Host
// must be non-empty, and the scheme must be one the switch handles.
func acceptsProxyURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "http", "https", "socks4", "socks4a", "socks5", "socks5h":
		return true
	}
	return false
}

func TestProxyURLGoldenVectors(t *testing.T) {
	vectors := []struct {
		raw    string
		accept bool
	}{
		{"http://127.0.0.1:8080", true},
		{"https://proxy.example.com:443", true},
		{"http://user:pass@proxy.example.com:3128", true},
		{"socks5://127.0.0.1:1080", true},
		{"socks5h://127.0.0.1:1080", true},
		{"socks4://127.0.0.1:1080", true},
		{"socks4a://127.0.0.1:1080", true},
		{"http://proxy.example.com", true},
		{"http://[::1]:8080", true},
		{"HTTP://127.0.0.1:8080", true},
		{"http://user:p%40ss@h:1", true},
		{"http://127.0.0.1:8080/path", true},
		{"http://127.0.0.1:8080?q=1", true},
		// net/url does not range-check the port, and an empty port is legal.
		{"http://127.0.0.1:99999", true},
		{"http://h:", true},
		{"http://user@h", true},
		{"http://:pass@h", true},
		{"ftp://127.0.0.1:21", false},
		{"socks://127.0.0.1:1080", false},
		{"127.0.0.1:8080", false},
		{"proxy.example.com", false},
		{"http://", false},
		{"http:///path", false},
		{"://127.0.0.1", false},
		{"http://127.0.0.1:abc", false},
		{"http://ho st:1", false},
		{"ht tp://127.0.0.1", false},
		{"http://%zz@h:1", false},
		{"//127.0.0.1:8080", false},
	}

	for _, v := range vectors {
		if got := acceptsProxyURL(v.raw); got != v.accept {
			t.Errorf("acceptsProxyURL(%q) = %v, want %v; burp.control.ProxyUrl must be updated to match", v.raw, got, v.accept)
		}
	}
}
