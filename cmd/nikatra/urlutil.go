package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

func NormalizeTarget(input string) (*url.URL, bool, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, false, errors.New("empty target")
	}
	defaulted := false
	if !strings.Contains(input, "://") {
		input = "https://" + input
		defaulted = true
	}
	u, err := url.Parse(input)
	if err != nil {
		return nil, false, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false, fmt.Errorf("unsupported URL scheme %q; use http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, false, errors.New("target host is required")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.Path = cleanURLPath(u.Path)
	u.RawPath = ""
	return u, defaulted, nil
}

func ResolveDefaultScheme(ctx context.Context, cfg *Config, httpsURL *url.URL) *url.URL {
	if httpsURL.Scheme != "https" {
		return httpsURL
	}
	if quickProbe(ctx, cfg, httpsURL) {
		return httpsURL
	}
	httpURL := copyURL(httpsURL)
	httpURL.Scheme = "http"
	if quickProbe(ctx, cfg, httpURL) {
		return httpURL
	}
	return httpsURL
}

func quickProbe(ctx context.Context, cfg *Config, u *url.URL) bool {
	client := &http.Client{Timeout: cfg.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, RootURL(u).String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Accept-Encoding", "identity")
		for _, kv := range cfg.CustomHeaders {
			req.Header.Set(kv.Name, kv.Value)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return resp.StatusCode > 0
	}
	return false
}

func cleanURLPath(p string) string {
	if p == "" {
		return "/"
	}
	trailing := strings.HasSuffix(p, "/")
	cleaned := pathpkg.Clean("/" + strings.TrimPrefix(p, "/"))
	if cleaned == "." {
		cleaned = "/"
	}
	if trailing && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func RootURL(u *url.URL) *url.URL {
	r := copyURL(u)
	r.Path = "/"
	r.RawQuery = ""
	r.Fragment = ""
	return r
}

func copyURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	v := *u
	return &v
}

func sameHost(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(normalizeHost(a.Host), normalizeHost(b.Host))
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && sameHost(a, b)
}

func normalizeHost(host string) string {
	h := strings.ToLower(host)
	if strings.HasSuffix(h, ":80") {
		return strings.TrimSuffix(h, ":80")
	}
	if strings.HasSuffix(h, ":443") {
		return strings.TrimSuffix(h, ":443")
	}
	return h
}

func BuildURL(base *url.URL, p string) *url.URL {
	if base == nil {
		return nil
	}
	p = strings.TrimSpace(p)
	if p == "" {
		p = "/"
	}
	parsed, err := url.Parse(p)
	if err == nil {
		var u *url.URL
		if parsed.IsAbs() {
			u = parsed
		} else {
			u = base.ResolveReference(parsed)
		}
		u.Fragment = ""
		u.Path = cleanURLPath(u.Path)
		u.RawPath = ""
		return u
	}
	u := copyURL(base)
	u.RawQuery = ""
	u.Fragment = ""
	if pathPart, queryPart, ok := strings.Cut(p, "?"); ok {
		u.Path = cleanURLPath(pathPart)
		u.RawQuery = queryPart
	} else {
		u.Path = cleanURLPath(p)
	}
	u.RawPath = ""
	return u
}

func normalizedURLKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	v := *u
	v.Fragment = ""
	v.Scheme = strings.ToLower(v.Scheme)
	v.Host = normalizeHost(v.Host)
	v.Path = cleanURLPath(v.Path)
	if v.RawQuery != "" {
		vals, err := url.ParseQuery(v.RawQuery)
		if err == nil {
			v.RawQuery = vals.Encode()
		}
	}
	return v.String()
}
