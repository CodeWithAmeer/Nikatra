package main

import (
	"net/http"
	"sort"
	"strings"
)

func AnalyzeHTTPMethods(resp *ResponseData) []Finding {
	if resp == nil {
		return nil
	}
	raw := strings.Join([]string{resp.Headers.Get("Allow"), resp.Headers.Get("Access-Control-Allow-Methods")}, ",")
	methods := parseMethods(raw)
	type methodMeta struct {
		Sev  Severity
		Conf int
		Why  string
	}
	risky := map[string]methodMeta{
		"PUT":       {SeverityLow, 55, "PUT can modify resources if enabled without proper authorization."},
		"DELETE":    {SeverityLow, 55, "DELETE can remove resources if enabled without proper authorization."},
		"PATCH":     {SeverityLow, 50, "PATCH can modify resources if enabled without proper authorization."},
		"TRACE":     {SeverityHigh, 85, "TRACE can enable Cross-Site Tracing risk in some environments."},
		"CONNECT":   {SeverityHigh, 85, "CONNECT is unusual on ordinary web origins and may indicate proxy behavior."},
		"PROPFIND":  {SeverityMedium, 75, "WebDAV-style methods increase attack surface when not required."},
		"PROPPATCH": {SeverityMedium, 75, "WebDAV-style methods increase attack surface when not required."},
		"MKCOL":     {SeverityMedium, 75, "WebDAV-style methods increase attack surface when not required."},
		"COPY":      {SeverityMedium, 75, "WebDAV-style methods increase attack surface when not required."},
		"MOVE":      {SeverityMedium, 75, "WebDAV-style methods increase attack surface when not required."},
		"LOCK":      {SeverityMedium, 70, "WebDAV-style methods increase attack surface when not required."},
		"UNLOCK":    {SeverityMedium, 70, "WebDAV-style methods increase attack surface when not required."},
	}
	var found []string
	severity := SeverityInfo
	confidence := 0
	var reasons []string
	for _, method := range sortedMethodKeys(methods) {
		meta, ok := risky[method]
		if !ok {
			continue
		}
		found = append(found, method)
		if severityRank[meta.Sev] > severityRank[severity] {
			severity = meta.Sev
		}
		if meta.Conf > confidence {
			confidence = meta.Conf
		}
		reasons = append(reasons, method+": "+meta.Why)
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	sort.Strings(reasons)
	name := "Potentially risky HTTP methods advertised"
	desc := "The server advertises HTTP methods that can increase attack surface if enabled unnecessarily. Nikatra only observed the OPTIONS response and did not send destructive methods."
	rec := "Disable unnecessary HTTP methods at the web server, application server, or reverse proxy. Confirm whether each method is required for an authenticated API before changing it."
	evidence := "OPTIONS advertised methods: " + strings.Join(found, ", ")
	if len(reasons) > 0 {
		evidence += "; " + strings.Join(reasons, " ")
	}
	return []Finding{NewFinding("risky-methods-advertised", name, "HTTP Methods", severity, confidence, resp.URL, http.MethodOptions, resp.StatusCode, evidence, desc, rec)}
}

func parseMethods(raw string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		f = strings.ToUpper(strings.TrimSpace(f))
		if f != "" {
			out[f] = true
		}
	}
	return out
}

func sortedMethodKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
