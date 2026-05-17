package main

import (
	"net/url"
	"strings"
)

func AnalyzePages(pages []PageData, base *url.URL) []Finding {
	var findings []Finding
	for _, page := range pages {
		if page.StatusCode >= 400 || len(page.Body) == 0 {
			continue
		}
		body := page.Body
		text := string(body)
		lower := strings.ToLower(text)
		if isDirectoryListing(body) {
			findings = append(findings, NewFinding("directory-listing", "Directory listing detected", "Information Disclosure", SeverityMedium, 90, page.URL, "GET", page.StatusCode, "Page contains directory index markers.", "A browsable directory listing exposes file names and may reveal sensitive files.", "Disable auto-indexing/directory browsing on the web server."))
		}
		if marker := firstMatch(lower, []string{"traceback (most recent call last)", "stack trace:", "exception details", "java.lang.", "system.stacktrace", "at org.springframework", "rails.root", "werkzeug debugger", "debugger active"}); marker != "" {
			findings = append(findings, NewFinding("stack-trace-disclosure", "Stack trace or debug error exposed", "Information Disclosure", SeverityHigh, 90, page.URL, "GET", page.StatusCode, "Observed marker: "+marker, "A page appears to expose internal stack traces or debug error information.", "Disable debug mode in production and return generic error pages."))
		}
		if marker := firstMatch(lower, []string{"sql syntax", "mysql_fetch", "ora-", "postgresql error", "sqlite_exception", "unclosed quotation mark after the character string", "you have an error in your sql syntax"}); marker != "" {
			findings = append(findings, NewFinding("database-error-disclosure", "Database error string exposed", "Information Disclosure", SeverityMedium, 85, page.URL, "GET", page.StatusCode, "Observed marker: "+marker, "A response appears to reveal database error details.", "Handle database errors server-side and return generic messages to users."))
		}
		if strings.Contains(lower, "phpinfo()") || (strings.Contains(lower, "php version") && strings.Contains(lower, "configuration")) {
			findings = append(findings, NewFinding("phpinfo-disclosure", "phpinfo output exposed", "Information Disclosure", SeverityHigh, 95, page.URL, "GET", page.StatusCode, "phpinfo-style content detected.", "A phpinfo page can expose environment variables, paths, modules, and configuration.", "Remove phpinfo pages from production and rotate any exposed secrets."))
		}
		if strings.Contains(lower, "swagger-ui") || strings.Contains(lower, "openapi") || strings.Contains(lower, "api-docs") {
			findings = append(findings, NewFinding("api-docs-visible", "API documentation appears public", "Information Disclosure", SeverityLow, 75, page.URL, "GET", page.StatusCode, "OpenAPI/Swagger marker detected.", "Public API documentation may reveal endpoints and models. This can be intended, but should be reviewed.", "Restrict internal API documentation or ensure it exposes only intended public APIs."))
		}
		if strings.Contains(lower, "sourceMappingURL=") {
			findings = append(findings, NewFinding("source-map-reference", "Source map reference found", "Information Disclosure", SeverityLow, 80, page.URL, "GET", page.StatusCode, "Response references a source map.", "Source maps may reveal original source code paths or comments if published.", "Remove production source maps or ensure they contain no sensitive code or comments."))
		}
		if strings.Contains(lower, "aws_access_key_id") || strings.Contains(lower, "metadata.google.internal") || strings.Contains(lower, "169.254.169.254") {
			findings = append(findings, NewFinding("cloud-metadata-reference", "Cloud metadata or credential reference exposed", "Information Disclosure", SeverityHigh, 85, page.URL, "GET", page.StatusCode, "Cloud metadata or credential-related marker detected.", "The response references cloud metadata or credential material.", "Remove cloud metadata references from public output and review for leaked secrets."))
		}
		if len(body) < 256*1024 && isTextLike(page.ContentType, body) {
			if secret := findSecretLikeString(text); secret != "" {
				findings = append(findings, NewFinding("secret-like-string", "Secret-looking string exposed", "Information Disclosure", SeverityHigh, 80, page.URL, "GET", page.StatusCode, "Observed secret-like marker: "+secret, "A small text response contains a value that resembles a secret or token.", "Remove secrets from public responses and rotate any exposed credentials."))
			}
		}
	}
	return findings
}

func AnalyzeSensitivePageCaching(pages []PageData) []Finding {
	var findings []Finding
	for _, page := range pages {
		if page.StatusCode >= 400 || !sensitiveLookingURL(page.URL) {
			continue
		}
		cc := strings.ToLower(page.Headers.Get("Cache-Control"))
		pragma := strings.ToLower(page.Headers.Get("Pragma"))
		if !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") && !strings.Contains(pragma, "no-cache") {
			findings = append(findings, NewFinding("sensitive-page-cache-control", "Sensitive-looking page lacks strong Cache-Control", "Security Headers", SeverityLow, 75, page.URL, "GET", page.StatusCode, "Cache-Control: "+emptyAs(page.Headers.Get("Cache-Control"), "missing"), "A sensitive-looking page does not include strong anti-caching directives.", "Add Cache-Control: no-store for authenticated or sensitive pages."))
		}
	}
	return findings
}
