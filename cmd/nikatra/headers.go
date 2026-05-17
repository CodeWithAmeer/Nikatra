package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func AnalyzeSecurityHeaders(resp *ResponseData, base *url.URL) ([]Finding, map[string]HeaderState) {
	var findings []Finding
	summary := map[string]HeaderState{}
	state := func(name, assessment string) {
		value := resp.Headers.Get(name)
		summary[name] = HeaderState{Name: name, Present: value != "", Value: truncateString(value, 300), Assessment: assessment}
	}
	add := func(checkID, name string, sev Severity, confidence int, headerName, desc, evidence, rec string) {
		findings = append(findings, NewFinding(checkID, name, "Security Headers", sev, confidence, resp.URL, resp.Method, resp.StatusCode, evidence, desc, rec))
		if _, ok := summary[headerName]; !ok {
			state(headerName, evidence)
		}
	}
	csp := resp.Headers.Get("Content-Security-Policy")
	if csp == "" {
		add("missing-csp", "Content-Security-Policy header missing", SeverityMedium, 90, "Content-Security-Policy", "The response does not include a Content-Security-Policy header.", "Header Content-Security-Policy is absent.", "Add a restrictive Content-Security-Policy header tailored to the application.")
		state("Content-Security-Policy", "missing")
	} else {
		weak := weakCSPMarkers(csp)
		if len(weak) > 0 {
			add("weak-csp", "Weak Content-Security-Policy directive", SeverityMedium, 85, "Content-Security-Policy", "The Content-Security-Policy header contains permissive directives.", "Observed weak directive(s): "+strings.Join(weak, ", "), "Tighten CSP directives, avoid unsafe-inline/unsafe-eval where possible, and restrict sources to trusted origins.")
			state("Content-Security-Policy", "weak: "+strings.Join(weak, ", "))
		} else {
			state("Content-Security-Policy", "present")
		}
		if !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			add("missing-csp-frame-ancestors", "CSP frame-ancestors directive missing", SeverityLow, 80, "Content-Security-Policy", "The CSP header does not include frame-ancestors.", "Content-Security-Policy present but frame-ancestors directive was not found.", "Add a frame-ancestors directive to control which origins can frame the application.")
		}
	}
	hsts := resp.Headers.Get("Strict-Transport-Security")
	if base.Scheme == "https" {
		if hsts == "" {
			add("missing-hsts", "Strict-Transport-Security header missing", SeverityMedium, 90, "Strict-Transport-Security", "The HTTPS response does not include Strict-Transport-Security.", "Header Strict-Transport-Security is absent on HTTPS.", "Add Strict-Transport-Security with an appropriate max-age and consider includeSubDomains after validation.")
			state("Strict-Transport-Security", "missing")
		} else {
			maxAge := parseHSTSMaxAge(hsts)
			if maxAge >= 0 && maxAge < 15552000 {
				add("weak-hsts", "Strict-Transport-Security max-age is short", SeverityLow, 85, "Strict-Transport-Security", "The HSTS max-age is shorter than common production recommendations.", fmt.Sprintf("Observed HSTS max-age=%d.", maxAge), "Use a longer HSTS max-age after confirming HTTPS is stable across the site.")
				state("Strict-Transport-Security", "short max-age")
			} else {
				state("Strict-Transport-Security", "present")
			}
		}
	} else {
		state("Strict-Transport-Security", "not applicable to HTTP response")
	}
	xfo := resp.Headers.Get("X-Frame-Options")
	if xfo == "" {
		add("missing-x-frame-options", "X-Frame-Options header missing", SeverityLow, 80, "X-Frame-Options", "The response does not include X-Frame-Options.", "Header X-Frame-Options is absent.", "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.")
		state("X-Frame-Options", "missing")
	} else {
		v := strings.ToUpper(strings.TrimSpace(xfo))
		if v != "DENY" && v != "SAMEORIGIN" && !strings.HasPrefix(v, "ALLOW-FROM") {
			add("weak-x-frame-options", "Weak X-Frame-Options value", SeverityLow, 85, "X-Frame-Options", "The X-Frame-Options value is not a commonly enforced value.", "Observed X-Frame-Options: "+xfo, "Use DENY or SAMEORIGIN, or migrate to CSP frame-ancestors.")
			state("X-Frame-Options", "weak")
		} else {
			state("X-Frame-Options", "present")
		}
	}
	xcto := resp.Headers.Get("X-Content-Type-Options")
	if strings.ToLower(strings.TrimSpace(xcto)) != "nosniff" {
		add("missing-x-content-type-options", "X-Content-Type-Options nosniff missing", SeverityLow, 85, "X-Content-Type-Options", "The response does not include X-Content-Type-Options: nosniff.", "Observed value: "+emptyAs(xcto, "missing"), "Add X-Content-Type-Options: nosniff to reduce MIME-sniffing risk.")
		state("X-Content-Type-Options", "missing or weak")
	} else {
		state("X-Content-Type-Options", "present")
	}
	referrer := resp.Headers.Get("Referrer-Policy")
	if referrer == "" {
		add("missing-referrer-policy", "Referrer-Policy header missing", SeverityLow, 80, "Referrer-Policy", "The response does not include a Referrer-Policy header.", "Header Referrer-Policy is absent.", "Add a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.")
		state("Referrer-Policy", "missing")
	} else if strings.EqualFold(strings.TrimSpace(referrer), "unsafe-url") {
		add("weak-referrer-policy", "Weak Referrer-Policy value", SeverityLow, 90, "Referrer-Policy", "The response uses a permissive Referrer-Policy value.", "Observed Referrer-Policy: "+referrer, "Use a less permissive policy such as strict-origin-when-cross-origin or no-referrer.")
		state("Referrer-Policy", "weak")
	} else {
		state("Referrer-Policy", "present")
	}
	for _, h := range []struct{ Name, CheckID, FindingName, Recommendation string }{
		{"Permissions-Policy", "missing-permissions-policy", "Permissions-Policy header missing", "Add a Permissions-Policy header to explicitly disable browser features the application does not need."},
		{"Cross-Origin-Opener-Policy", "missing-coop", "Cross-Origin-Opener-Policy header missing", "Consider Cross-Origin-Opener-Policy: same-origin for applications that benefit from cross-origin isolation."},
		{"Cross-Origin-Resource-Policy", "missing-corp", "Cross-Origin-Resource-Policy header missing", "Consider Cross-Origin-Resource-Policy for sensitive resources that should not be embedded cross-origin."},
		{"Cross-Origin-Embedder-Policy", "missing-coep", "Cross-Origin-Embedder-Policy header missing", "Consider Cross-Origin-Embedder-Policy where cross-origin isolation is required by the application."},
	} {
		if resp.Headers.Get(h.Name) == "" {
			add(h.CheckID, h.FindingName, SeverityInfo, 75, h.Name, "The response does not include "+h.Name+".", "Header "+h.Name+" is absent.", h.Recommendation)
			state(h.Name, "missing")
		} else {
			state(h.Name, "present")
		}
	}
	server := resp.Headers.Get("Server")
	if server != "" {
		sev, confidence, checkID := SeverityInfo, 80, "server-header-leak"
		if looksLikeVersionLeak(server) {
			sev, confidence, checkID = SeverityLow, 90, "server-version-leak"
		}
		add(checkID, "Server header exposes implementation details", sev, confidence, "Server", "The Server header exposes web server implementation details.", "Server: "+truncateString(server, 200), "Reduce or remove server banner details at the web server or reverse proxy layer.")
		state("Server", "present")
	} else {
		state("Server", "not present")
	}
	xpb := resp.Headers.Get("X-Powered-By")
	if xpb != "" {
		add("x-powered-by-leak", "X-Powered-By header exposes framework details", SeverityLow, 90, "X-Powered-By", "The X-Powered-By header exposes application framework or runtime information.", "X-Powered-By: "+truncateString(xpb, 200), "Disable framework version and banner headers such as X-Powered-By.")
		state("X-Powered-By", "present")
	} else {
		state("X-Powered-By", "not present")
	}
	return findings, summary
}

func weakCSPMarkers(csp string) []string {
	lower := strings.ToLower(csp)
	markers := []string{"'unsafe-inline'", "'unsafe-eval'", "default-src *", "script-src *", "object-src *", "img-src *", "connect-src *", "frame-src *", "style-src *"}
	var weak []string
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			weak = append(weak, marker)
		}
	}
	return weak
}

func parseHSTSMaxAge(v string) int {
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			n, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
			if err == nil {
				return n
			}
		}
	}
	return -1
}
