package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type headerList []HeaderKV

func looksStaticPath(p string) bool {
	p = strings.ToLower(p)
	staticExt := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".mp4", ".mp3", ".avi", ".mov", ".webm", ".xml", ".json", ".txt", ".csv"}
	for _, ext := range staticExt {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func isTextLike(ct string, body []byte) bool {
	ct = strings.ToLower(ct)
	if strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "javascript") || strings.Contains(ct, "x-www-form-urlencoded") {
		return true
	}
	return len(body) < 512*1024 && !isLikelyBinary(body)
}

func isLikelyBinary(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	limit := minInt(len(body), 1024)
	zeros := 0
	bad := 0
	for _, b := range body[:limit] {
		if b == 0 {
			zeros++
		}
		if b < 9 || (b > 13 && b < 32) {
			bad++
		}
	}
	return zeros > 0 || float64(bad)/float64(limit) > 0.08
}

func versionFromText(text, marker string) string {
	if text == "" {
		return ""
	}
	quoted := regexp.QuoteMeta(marker)
	patterns := []string{
		`(?i)` + quoted + `[ /_-]*v?([0-9]+(?:\.[0-9]+){0,3})`,
		`(?i)\b([0-9]+(?:\.[0-9]+){1,3})\b`,
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func oldVersionHint(name, version string) string {
	if version == "" {
		return ""
	}
	major := parseMajor(version)
	if major < 0 {
		return ""
	}
	switch strings.ToLower(name) {
	case "php":
		if major < 8 {
			return "PHP major version appears older than 8."
		}
	case "apache":
		if major < 2 {
			return "Apache major version appears very old."
		}
	case "nginx":
		if major == 0 {
			return "nginx major version appears very old."
		}
	case "drupal":
		if major < 10 {
			return "Drupal major version appears older than current supported major releases."
		}
	case "joomla":
		if major < 4 {
			return "Joomla major version appears older than current supported major releases."
		}
	case "wordpress":
		if major < 6 {
			return "WordPress major version appears older than current mainstream releases."
		}
	case "node.js", "node":
		if major < 18 {
			return "Node.js major version appears old."
		}
	case "rails":
		if major < 7 {
			return "Rails major version appears old."
		}
	case "django":
		if major < 4 {
			return "Django major version appears old."
		}
	}
	return ""
}

func parseMajor(version string) int {
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimLeft(parts[0], "vV"))
	if err != nil {
		return -1
	}
	return n
}

func sensitiveLookingURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	markers := []string{"login", "admin", "account", "dashboard", "profile", "settings", "checkout", "billing", "password"}
	for _, marker := range markers {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func normalizeScanProfile(raw string) (string, error) {
	profile := strings.ToLower(strings.TrimSpace(raw))
	if profile == "" {
		profile = "basic"
	}
	switch profile {
	case "basic", "standard", "full", "paranoid":
		return profile, nil
	default:
		return "", fmt.Errorf("unsupported scan profile %q; use basic, standard, full, or paranoid", raw)
	}
}

func filterPathChecksByMinimumSeverity(checks []PathCheck, min Severity) []PathCheck {
	minRank := severityRank[min]
	out := make([]PathCheck, 0, len(checks))
	for _, check := range checks {
		if severityRank[check.Severity] >= minRank {
			out = append(out, check)
		}
	}
	return out
}

func checkEnabled(cfg *Config, id string) bool {
	id = strings.ToLower(id)
	if len(cfg.IncludeChecks) > 0 && !cfg.IncludeChecks[id] {
		return false
	}
	if cfg.ExcludeChecks[id] {
		return false
	}
	return true
}

func confirmExpandedSecretConfig(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	path := responsePath(resp)
	text := string(firstN(resp.Body, 512*1024))
	lower := strings.ToLower(text)
	if strings.Contains(lower, "-----begin openssh private key-----") || strings.Contains(lower, "-----begin rsa private key-----") || strings.Contains(lower, "-----begin dsa private key-----") || strings.Contains(lower, "-----begin ec private key-----") || strings.Contains(lower, "-----begin private key-----") {
		return true, 99, "Private key PEM/OpenSSH marker detected."
	}
	if strings.Contains(path, ".env") {
		return confirmEnvFile(resp, soft)
	}
	if secret := findSecretLikeString(text); secret != "" {
		return true, 94, "Secret-like configuration value detected: " + truncateString(secret, 180)
	}
	markers := []string{"password", "passwd", "secret", "token", "apikey", "api_key", "client_secret", "private_key", "connectionstring", "database_url", "jdbc:", "redis://", "mongodb://", "postgres://", "mysql://", "aws_access_key_id", "aws_secret_access_key", "smtp_password", "stripe_", "sendgrid", "sentry_dsn", "jwt_secret"}
	matched := countContains(lower, markers)
	structured := looksLikeStructuredConfig(path, lower)
	if matched >= 1 && structured {
		return true, 88, fmt.Sprintf("Sensitive configuration keyword and structured config markers detected (%d marker matches).", matched)
	}
	if matched >= 2 {
		return true, 82, fmt.Sprintf("Multiple sensitive configuration keywords detected (%d marker matches).", matched)
	}
	if structured && strings.Contains(path, "config") || structured && strings.Contains(path, "settings") || structured && strings.Contains(path, "application") {
		return true, 72, "Structured configuration file markers detected at a sensitive-looking path."
	}
	return false, 0, ""
}

func confirmExpandedBackup(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	path := responsePath(resp)
	lowerPath := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lowerPath, ".zip"):
		return confirmArchive(resp, soft)
	case strings.HasSuffix(lowerPath, ".tar.gz") || strings.HasSuffix(lowerPath, ".tgz") || strings.HasSuffix(lowerPath, ".gz"):
		return confirmArchive(resp, soft)
	case strings.HasSuffix(lowerPath, ".sql") || strings.HasSuffix(lowerPath, ".sql.gz"):
		return confirmSQLDump(resp, soft)
	}
	if looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	text := string(firstN(resp.Body, 512*1024))
	lower := strings.ToLower(text)
	if secret := findSecretLikeString(text); secret != "" {
		return true, 92, "Secret-like value in backup copy detected: " + truncateString(secret, 180)
	}
	codeMarkers := []string{"<?php", "package main", "import (", "def ", "class ", "function ", "module.exports", "export default", "using system", "public class", "namespace ", "<configuration", "<appsettings", "db_password", "database_url", "connectionstrings", "jdbc:", "spring.datasource", "django_secret_key", "secret_key"}
	matched := countContains(lower, codeMarkers)
	if matched >= 1 && backupLikePath(lowerPath) {
		return true, 86, fmt.Sprintf("Backup extension with source/config marker detected (%d marker matches).", matched)
	}
	return false, 0, ""
}

func confirmExpandedLogFile(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	text := string(firstN(resp.Body, 512*1024))
	lower := strings.ToLower(text)
	markers := []string{" error ", "warn", "warning", "exception", "traceback", "stack trace", " fatal", "panic:", "segmentation fault", "request_id", "level=", "timestamp", " at ", " caused by:", "sqlstate", "errno", "failed", "denied"}
	matched := countContains(lower, markers)
	hasDate := regexp.MustCompile(`(?m)\b(?:20\d\d[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}/[A-Za-z]{3}/20\d\d|\[[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2})`).FindString(text) != ""
	if matched >= 2 || matched >= 1 && hasDate {
		return true, 88, fmt.Sprintf("Log-like content markers detected (%d markers, timestamp=%t).", matched, hasDate)
	}
	if secret := findSecretLikeString(text); secret != "" {
		return true, 90, "Secret-like value appears in exposed log: " + truncateString(secret, 180)
	}
	return false, 0, ""
}

func confirmExpandedManifest(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	if ok, conf, evidence := confirmPackageManifest(resp, soft); ok {
		return ok, conf, evidence
	}
	path := responsePath(resp)
	text := string(firstN(resp.Body, 512*1024))
	lower := strings.ToLower(text)
	switch {
	case strings.HasSuffix(path, "requirements.txt") || strings.Contains(path, "requirements-"):
		if regexp.MustCompile(`(?m)^[a-zA-Z0-9_.-]+\s*(==|>=|<=|~=|>|<)\s*[0-9]`).FindString(text) != "" {
			return true, 94, "Python requirements dependency pins detected."
		}
	case strings.HasSuffix(path, "pipfile") || strings.HasSuffix(path, "pipfile.lock") || strings.HasSuffix(path, "pyproject.toml") || strings.HasSuffix(path, "poetry.lock"):
		if countContains(lower, []string{"[tool.poetry", "[[package]]", "[packages]", "python_version", "poetry.lock"}) >= 1 {
			return true, 92, "Python project manifest markers detected."
		}
	case strings.HasSuffix(path, "gemfile") || strings.HasSuffix(path, "gemfile.lock") || strings.HasSuffix(path, "rakefile") || strings.HasSuffix(path, "config.ru"):
		if countContains(lower, []string{"source \"https://rubygems.org\"", "gem ", "bundled with", "rails", "rack"}) >= 1 {
			return true, 92, "Ruby/Bundler manifest markers detected."
		}
	case strings.HasSuffix(path, "cargo.toml") || strings.HasSuffix(path, "cargo.lock"):
		if countContains(lower, []string{"[package]", "[dependencies]", "[[package]]", "checksum ="}) >= 1 {
			return true, 94, "Rust Cargo manifest markers detected."
		}
	case strings.HasSuffix(path, "dockerfile") || strings.Contains(path, "docker-compose"):
		if countContains(lower, []string{"from ", "services:", "image:", "build:", "container_name:", "ports:"}) >= 1 {
			return true, 92, "Docker build/deployment manifest markers detected."
		}
	case strings.Contains(path, "jenkinsfile") || strings.Contains(path, "gitlab-ci") || strings.Contains(path, "pipelines") || strings.Contains(path, "workflows") || strings.Contains(path, "travis") || strings.Contains(path, "circleci"):
		if countContains(lower, []string{"pipeline", "stages:", "jobs:", "steps:", "script:", "deploy", "checkout", "uses:"}) >= 1 {
			return true, 88, "CI/CD pipeline manifest markers detected."
		}
	case strings.HasSuffix(path, ".tf") || strings.Contains(path, "terraform") || strings.Contains(path, "ansible") || strings.Contains(path, "playbook") || strings.Contains(path, "kustomization") || strings.Contains(path, "chart.yaml") || strings.Contains(path, "values.yaml"):
		if countContains(lower, []string{"resource \"", "provider \"", "variable \"", "apiVersion:", "kind:", "hosts:", "tasks:", "chart", "helm"}) >= 1 {
			return true, 88, "Infrastructure/deployment manifest markers detected."
		}
	case strings.Contains(path, "manifest.mf"):
		if countContains(lower, []string{"manifest-version:", "implementation-version:", "built-by:", "main-class:"}) >= 1 {
			return true, 90, "Java MANIFEST.MF markers detected."
		}
	}
	if secret := findSecretLikeString(text); secret != "" {
		return true, 90, "Manifest contains secret-like value: " + truncateString(secret, 180)
	}
	return false, 0, ""
}

func confirmExpandedAdminSurface(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if ok, conf, evidence := confirmAdminPanel(resp, soft); ok {
		return ok, conf, evidence
	}
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(firstN(resp.Body, 256*1024)))
	markers := []string{"swagger-ui", "openapi", "redoc", "grafana", "kibana", "jenkins", "sonarqube", "phpmyadmin", "adminer", "pgadmin", "graphql", "graphiql", "prometheus", "metrics", "actuator"}
	matched := countContains(lower, markers)
	if matched >= 1 && looksLikeHTML(resp.Body) || matched >= 2 {
		return true, 78, fmt.Sprintf("Administrative/documentation surface marker detected (%d marker matches).", matched)
	}
	return false, 0, ""
}

func confirmExpandedSourceMap(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	var obj map[string]interface{}
	if json.Unmarshal(resp.Body, &obj) != nil {
		return false, 0, ""
	}
	_, hasVersion := obj["version"]
	_, hasSources := obj["sources"]
	_, hasMappings := obj["mappings"]
	if hasVersion && hasSources && hasMappings {
		return true, 98, "Valid source map JSON with version, sources, and mappings fields detected."
	}
	return false, 0, ""
}

func confirmExpandedDiscoveryFile(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	path := responsePath(resp)
	lower := strings.ToLower(string(firstN(resp.Body, 256*1024)))
	switch {
	case strings.Contains(path, "robots"):
		if strings.Contains(lower, "user-agent:") || strings.Contains(lower, "disallow:") {
			return true, 94, "robots.txt directives detected."
		}
	case strings.Contains(path, "sitemap"):
		if strings.Contains(lower, "<urlset") || strings.Contains(lower, "<sitemapindex") {
			return true, 94, "Sitemap XML markers detected."
		}
	case strings.Contains(path, "security.txt"):
		if strings.Contains(lower, "contact:") || strings.Contains(lower, "expires:") || strings.Contains(lower, "policy:") {
			return true, 94, "security.txt fields detected."
		}
	case strings.Contains(path, "openid-configuration") || strings.Contains(path, "jwks") || strings.Contains(path, "oauth"):
		if strings.Contains(lower, "issuer") || strings.Contains(lower, "jwks_uri") || strings.Contains(lower, "authorization_endpoint") || strings.Contains(lower, "keys") {
			return true, 90, "Identity discovery JSON markers detected."
		}
	case strings.Contains(path, "assetlinks") || strings.Contains(path, "apple-app-site-association"):
		if strings.Contains(lower, "sha256_cert_fingerprints") || strings.Contains(lower, "applinks") || strings.Contains(lower, "webcredentials") {
			return true, 90, "Mobile app association markers detected."
		}
	default:
		if len(strings.TrimSpace(lower)) > 0 && len(lower) < 128*1024 {
			return true, 70, "Small public discovery/policy file content detected."
		}
	}
	return false, 0, ""
}

func responsePath(resp *ResponseData) string {
	if resp == nil {
		return ""
	}
	raw := resp.FinalURL
	if raw == "" {
		raw = resp.URL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	return strings.ToLower(u.Path)
}

func countContains(s string, markers []string) int {
	count := 0
	for _, marker := range markers {
		if marker != "" && strings.Contains(s, strings.ToLower(marker)) {
			count++
		}
	}
	return count
}

func looksLikeStructuredConfig(path, lower string) bool {
	if strings.HasSuffix(path, ".json") {
		var obj map[string]interface{}
		return json.Unmarshal([]byte(lower), &obj) == nil
	}
	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		return regexp.MustCompile(`(?m)^[a-zA-Z0-9_.-]+:\s*`).FindString(lower) != ""
	}
	if strings.HasSuffix(path, ".properties") || strings.HasSuffix(path, ".ini") || strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".cfg") || strings.Contains(path, ".env") || strings.HasSuffix(path, "rc") {
		return regexp.MustCompile(`(?m)^[a-zA-Z0-9_.-]+\s*(=|:)\s*[^\s#]+`).FindString(lower) != ""
	}
	if strings.HasSuffix(path, ".xml") || strings.Contains(path, "web.config") {
		return strings.Contains(lower, "<configuration") || strings.Contains(lower, "<appsettings") || strings.Contains(lower, "<connectionstrings")
	}
	return false
}

func backupLikePath(lowerPath string) bool {
	return strings.HasSuffix(lowerPath, ".bak") || strings.HasSuffix(lowerPath, ".backup") || strings.HasSuffix(lowerPath, ".old") || strings.HasSuffix(lowerPath, ".orig") || strings.HasSuffix(lowerPath, ".save") || strings.HasSuffix(lowerPath, ".copy") || strings.HasSuffix(lowerPath, ".tmp") || strings.HasSuffix(lowerPath, ".swp") || strings.HasSuffix(lowerPath, "~")
}

func responseUsable(resp *ResponseData, soft *Soft404Profile) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == 404 || resp.StatusCode == 410 || resp.StatusCode >= 500 {
		return false
	}
	if soft != nil && soft.IsSoft404(resp) {
		return false
	}
	return true
}

func confirmGitDirectory(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "index of /.git") || strings.Contains(lower, "config") && strings.Contains(lower, "objects") && strings.Contains(lower, "refs") {
		return true, 90, "Directory listing contains Git repository markers."
	}
	return false, 0, ""
}

func confirmGitConfig(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	body := string(resp.Body)
	if strings.Contains(body, "[core]") && strings.Contains(body, "repositoryformatversion") {
		return true, 98, "Git config markers [core] and repositoryformatversion detected."
	}
	return false, 0, ""
}

func confirmEnvFile(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	text := string(resp.Body)
	envRe := regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=.{1,}`)
	secretRe := regexp.MustCompile(`(?im)^(?:APP_KEY|SECRET|.*SECRET.*|.*TOKEN.*|.*PASSWORD.*|.*PASS.*|.*KEY.*|DATABASE_URL|DB_PASSWORD|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)=.+`)
	envMatches := envRe.FindAllString(text, 20)
	secret := secretRe.FindString(text)
	if len(envMatches) >= 2 && secret != "" {
		return true, 99, "Environment variable patterns and secret-like key detected: " + truncateString(secret, 180)
	}
	if len(envMatches) >= 4 {
		return true, 85, fmt.Sprintf("%d environment variable assignments detected.", len(envMatches))
	}
	return false, 0, ""
}

func confirmArchive(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || len(resp.Body) < 4 || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	path := strings.ToLower(resp.URL)
	ct := strings.ToLower(resp.Headers.Get("Content-Type"))
	if strings.HasSuffix(path, ".zip") && bytes.HasPrefix(resp.Body, []byte{'P', 'K', 0x03, 0x04}) {
		return true, 99, "ZIP magic bytes PK\\x03\\x04 detected; Content-Type: " + emptyAs(ct, "missing")
	}
	if (strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".tar.gz")) && len(resp.Body) >= 2 && resp.Body[0] == 0x1f && resp.Body[1] == 0x8b {
		evidence := "gzip magic bytes detected"
		if zr, err := gzip.NewReader(bytes.NewReader(resp.Body)); err == nil {
			buf := make([]byte, 512)
			n, _ := zr.Read(buf)
			zr.Close()
			if n > 0 {
				evidence += "; decompressible gzip stream"
			}
		}
		return true, 98, evidence + "; Content-Type: " + emptyAs(ct, "missing")
	}
	return false, 0, ""
}

func confirmSQLDump(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	text := string(resp.Body)
	lower := strings.ToLower(text)
	markers := []string{"create table", "insert into", "-- mysql dump", "postgresql database dump", "sqlite format 3", "dumped by pg_dump", "drop table if exists"}
	count := 0
	var seen []string
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			count++
			seen = append(seen, marker)
		}
	}
	if count >= 2 || strings.Contains(lower, "sqlite format 3") {
		return true, 98, "SQL dump markers detected: " + strings.Join(seen, ", ")
	}
	return false, 0, ""
}

func confirmDSStore(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || len(resp.Body) < 16 || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	if bytes.Contains(resp.Body[:minInt(len(resp.Body), 256)], []byte("Bud1")) {
		return true, 99, ".DS_Store Bud1 binary marker detected."
	}
	return false, 0, ""
}

func confirmPHPInfo(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "phpinfo()") && strings.Contains(lower, "php version") {
		return true, 98, "phpinfo() and PHP Version markers detected."
	}
	return false, 0, ""
}

func confirmApacheStatus(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "apache server status") || strings.Contains(lower, "server version:") && strings.Contains(lower, "server uptime") || strings.Contains(lower, "apache server information") {
		return true, 92, "Apache status/info markers detected."
	}
	return false, 0, ""
}

func confirmAdminPanel(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || resp.StatusCode >= 500 {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true, 70, fmt.Sprintf("Administrative path returned HTTP %d.", resp.StatusCode)
	}
	markers := []string{"admin", "administrator", "login", "password", "username", "wp-login.php", "dashboard", "sign in"}
	matches := 0
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			matches++
		}
	}
	if matches >= 2 && looksLikeHTML(resp.Body) {
		return true, 75, fmt.Sprintf("Login/admin markers detected (%d markers).", matches)
	}
	return false, 0, ""
}

func confirmWordPressSurface(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "wp-content") || strings.Contains(lower, "wp-includes") || strings.Contains(lower, "wp-json") || strings.Contains(lower, "wordpress") || strings.Contains(resp.URL, "xmlrpc.php") && resp.StatusCode < 500 {
		return true, 80, "WordPress marker visible at endpoint."
	}
	return false, 0, ""
}

func confirmJoomlaSurface(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "joomla") || strings.Contains(lower, "administrator") && strings.Contains(lower, "login") {
		return true, 80, "Joomla marker visible at endpoint."
	}
	return false, 0, ""
}

func confirmDrupalSurface(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "drupal") || strings.Contains(lower, "drupal.org") || strings.Contains(lower, "user/login") {
		return true, 80, "Drupal marker visible at endpoint."
	}
	return false, 0, ""
}

func confirmSecurityTxt(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "contact:") || strings.Contains(lower, "expires:") || strings.Contains(lower, "policy:") {
		return true, 95, "security.txt fields detected."
	}
	return false, 0, ""
}

func confirmDebugEndpoint(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "cmdline") && strings.Contains(lower, "memstats") || strings.Contains(lower, "debug vars") || strings.Contains(lower, "runtime.memstats") || strings.Contains(lower, "expvar") {
		return true, 92, "Debug/expvar markers detected."
	}
	return false, 0, ""
}

func confirmActuator(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "_links") && strings.Contains(lower, "actuator") || strings.Contains(lower, "spring") && strings.Contains(lower, "management") || strings.Contains(lower, "jvm_memory") || strings.Contains(lower, "applicationconfig") || strings.Contains(lower, "propertysources") {
		sevEvidence := "Spring actuator/prometheus markers detected."
		return true, 90, sevEvidence
	}
	return false, 0, ""
}

func confirmAPIDocs(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "swagger-ui") || strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") && strings.Contains(lower, "paths") || strings.Contains(lower, "api-docs") {
		return true, 88, "Swagger/OpenAPI markers detected."
	}
	return false, 0, ""
}

func confirmWebXML(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "<web-app") && strings.Contains(lower, "</web-app>") {
		return true, 98, "WEB-INF web.xml markers detected."
	}
	return false, 0, ""
}

func confirmConfigBackup(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	text := string(resp.Body)
	lower := strings.ToLower(text)
	if strings.Contains(lower, "<?php") && (strings.Contains(lower, "db_password") || strings.Contains(lower, "database") || strings.Contains(lower, "wp-config") || strings.Contains(lower, "define('db_")) {
		return true, 98, "PHP configuration markers and database-related keys detected."
	}
	if secret := findSecretLikeString(text); secret != "" {
		return true, 90, "Secret-like configuration value detected: " + secret
	}
	return false, 0, ""
}

func confirmPackageManifest(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) || !isTextLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
		return false, 0, ""
	}
	path := strings.ToLower(resp.URL)
	body := string(resp.Body)
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(path, "package.json"):
		var obj map[string]interface{}
		if json.Unmarshal(resp.Body, &obj) == nil {
			if _, ok := obj["dependencies"]; ok {
				return true, 98, "Valid package.json with dependencies object detected."
			}
			if _, ok := obj["devDependencies"]; ok {
				return true, 95, "Valid package.json with devDependencies object detected."
			}
		}
	case strings.Contains(path, "composer.json"):
		var obj map[string]interface{}
		if json.Unmarshal(resp.Body, &obj) == nil {
			if _, ok := obj["require"]; ok {
				return true, 98, "Valid composer.json with require object detected."
			}
		}
	case strings.Contains(path, "composer.lock"):
		if strings.Contains(lower, "\"packages\"") && strings.Contains(lower, "\"content-hash\"") {
			return true, 98, "composer.lock markers detected."
		}
	case strings.Contains(path, "package-lock.json"):
		if strings.Contains(lower, "\"lockfileversion\"") && strings.Contains(lower, "\"packages\"") {
			return true, 98, "package-lock.json markers detected."
		}
	case strings.Contains(path, "yarn.lock"):
		if strings.Contains(lower, "integrity sha") || strings.Contains(lower, "yarn lockfile") {
			return true, 95, "yarn.lock markers detected."
		}
	case strings.Contains(path, "pnpm-lock.yaml"):
		if strings.Contains(lower, "lockfileversion:") && strings.Contains(lower, "packages:") {
			return true, 95, "pnpm-lock.yaml markers detected."
		}
	case strings.Contains(path, "go.mod"):
		if strings.Contains(lower, "module ") && strings.Contains(lower, "go ") {
			return true, 98, "go.mod module and go directives detected."
		}
	case strings.Contains(path, "go.sum"):
		if strings.Contains(lower, " h1:") {
			return true, 95, "go.sum checksum markers detected."
		}
	case strings.Contains(path, "pom.xml"):
		if strings.Contains(lower, "<project") && strings.Contains(lower, "<dependencies") {
			return true, 98, "Maven pom.xml markers detected."
		}
	}
	return false, 0, ""
}

func confirmCrossDomainPolicy(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "<cross-domain-policy") || strings.Contains(lower, "<access-policy") {
		conf := 85
		evidence := "Legacy cross-domain policy XML detected."
		if strings.Contains(lower, "domain=\"*\"") || strings.Contains(lower, "domain='*'") {
			conf = 95
			evidence += " Wildcard domain is present."
		}
		return true, conf, evidence
	}
	return false, 0, ""
}

func isDirectoryListing(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "<title>index of /") || strings.Contains(lower, "directory listing for") || strings.Contains(lower, "parent directory</a>") || strings.Contains(lower, "<h1>index of")
}

func firstMatch(s string, markers []string) string {
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return marker
		}
	}
	return ""
}

func sanitizeEvidence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	privateKeyRe := regexp.MustCompile(`(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`)
	s = privateKeyRe.ReplaceAllString(s, "<private-key:redacted>")
	privateKeyMarkerRe := regexp.MustCompile(`(?i)-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`)
	s = privateKeyMarkerRe.ReplaceAllString(s, "<private-key-marker:redacted>")
	bearerRe := regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,})`)
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		parts := strings.Fields(m)
		if len(parts) < 2 {
			return "Bearer <redacted>"
		}
		return "Bearer <redacted:" + redactionHash(parts[1]) + ">"
	})
	basicRe := regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}`)
	s = basicRe.ReplaceAllString(s, "Basic <redacted>")
	jwtRe := regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	s = jwtRe.ReplaceAllStringFunc(s, func(m string) string { return "<jwt:redacted:" + redactionHash(m) + ">" })
	awsRe := regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	s = awsRe.ReplaceAllStringFunc(s, func(m string) string { return "<aws-access-key-id:redacted:" + redactionHash(m) + ">" })
	urlParamRe := regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|signature|sig)=)([^&#\s]+)`)
	s = urlParamRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlParamRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return sub[1] + "<redacted:" + redactionHash(sub[2]) + ">"
	})
	kvRe := regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|token|password|passwd|private[_-]?key|aws_access_key_id|aws_secret_access_key|client_secret|app_key|secret_key|jwt_secret|db_password|database_url|authorization|cookie)\b\s*([:=])\s*["']?([^"'\s;,]{6,})["']?`)
	s = kvRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvRe.FindStringSubmatch(m)
		if len(sub) < 4 {
			return m
		}
		return sub[1] + sub[2] + "<redacted:" + redactionHash(sub[3]) + ">"
	})
	return s
}

func redactionHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:10]
}

func sanitizeStringSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, sanitizeEvidence(v))
	}
	return out
}

func findSecretLikeString(text string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["']?[^"'\s]{8,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	}
	for _, re := range patterns {
		if m := re.FindString(text); m != "" {
			return truncateString(sanitizeEvidence(m), 180)
		}
	}
	return ""
}

func baselineKey(f Finding) string {
	u := f.URL
	if parsed, err := url.Parse(f.URL); err == nil {
		path := cleanURLPath(parsed.Path)
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		u = normalizeHost(parsed.Host) + path
	}
	return strings.ToLower(f.CheckID + "|" + u)
}

func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func findingHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func randomToken(n int) string {
	if n <= 0 {
		n = 6
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

func truncateString(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func safeTextPreview(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if isLikelyBinary(body) {
		return "[binary content omitted]"
	}
	return string(firstN(body, 512))
}

func firstN(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func extractTitle(body []byte) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := html.UnescapeString(string(m[1]))
	title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
	return truncateString(title, 180)
}

func emptyAs(s, replacement string) string {
	if strings.TrimSpace(s) == "" {
		return replacement
	}
	return s
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	re := regexp.MustCompile(`[^a-z0-9]+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "item"
	}
	return s
}

func clampInt(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

type NikatraJSONConfig struct {
	Target        string          `json:"target"`
	Concurrency   *int            `json:"concurrency"`
	Timeout       string          `json:"timeout"`
	UserAgent     string          `json:"user_agent"`
	OutputFormat  string          `json:"output_format"`
	Output        string          `json:"output"`
	RateLimit     *float64        `json:"rate_limit"`
	MaxRedirects  *int            `json:"max_redirects"`
	Depth         *int            `json:"depth"`
	MaxPages      *int            `json:"max_pages"`
	ResponseLimit *int64          `json:"response_limit"`
	Retries       *int            `json:"retries"`
	Authorized    *bool           `json:"authorized"`
	AllowExternal *bool           `json:"allow_external"`
	FollowSitemap *bool           `json:"follow_sitemap"`
	FollowRobots  *bool           `json:"follow_robots"`
	RespectRobots *bool           `json:"respect_robots"`
	SafeMode      *bool           `json:"safe_mode"`
	ScanProfile   string          `json:"scan_profile"`
	Verbose       *bool           `json:"verbose"`
	Headers       json.RawMessage `json:"headers"`
	Include       []string        `json:"include"`
	Exclude       []string        `json:"exclude"`
	Templates     string          `json:"templates"`
	Baseline      string          `json:"baseline"`
	FailOn        string          `json:"fail_on"`
	Cookie        string          `json:"cookie"`
	BearerToken   string          `json:"bearer_token"`
	BasicAuth     string          `json:"basic_auth"`
}

func parseConfigHeaders(raw json.RawMessage) ([]HeaderKV, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		var out []HeaderKV
		for _, h := range list {
			var hl headerList
			if err := hl.Set(h); err != nil {
				return nil, err
			}
			out = append(out, hl...)
		}
		return out, nil
	}
	var obj map[string]string
	if err := json.Unmarshal(raw, &obj); err == nil {
		out := make([]HeaderKV, 0, len(obj))
		for k, v := range obj {
			out = append(out, HeaderKV{Name: k, Value: v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	return nil, errors.New("config headers must be an object or array of 'Name: value' strings")
}

func verbosef(cfg *Config, format string, args ...any) {
	if cfg != nil && cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[nikatra] "+format+"\n", args...)
	}
}

func intInSlice(n int, xs []int) bool {
	for _, x := range xs {
		if n == x {
			return true
		}
	}
	return false
}

func (p *RobotsPolicy) Allowed(path string) bool {
	if p == nil {
		return true
	}
	if path == "" {
		path = "/"
	}
	bestAllow, bestDisallow := -1, -1
	for _, a := range p.Allow {
		if robotsMatch(a, path) && len(a) > bestAllow {
			bestAllow = len(a)
		}
	}
	for _, d := range p.Disallow {
		if robotsMatch(d, path) && len(d) > bestDisallow {
			bestDisallow = len(d)
		}
	}
	return bestDisallow < 0 || bestAllow >= bestDisallow
}

func (cfg *Config) IsRobotsBlocked(u *url.URL) bool {
	if cfg == nil || !cfg.RespectRobots || cfg.RobotsPolicy == nil || u == nil {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return !cfg.RobotsPolicy.Allowed(path)
}

func (cfg *Config) IsCrawlBlocked(u *url.URL) bool {
	return cfg.IsRobotsBlocked(u)
}

func (p *Soft404Profile) Decision(resp *ResponseData) (bool, int, string) {
	if p == nil || resp == nil {
		return false, 0, ""
	}
	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		return true, 100, fmt.Sprintf("status=%d", resp.StatusCode)
	}
	if hasUniquePageKeywords(resp.Body) {
		return false, 0, "unique admin/login/debug keywords"
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Headers.Get("Location")
		for _, sample := range p.Samples {
			if sample.StatusCode >= 300 && sample.StatusCode < 400 && redirectsSimilar(sample.Location, loc) {
				return true, 85, "redirect similar to nonexistent path"
			}
		}
		return false, 0, ""
	}
	if resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 403 {
		return false, 0, ""
	}
	title := extractTitle(resp.Body)
	length := len(resp.Body)
	contentType := firstHeaderToken(resp.Headers.Get("Content-Type"))
	hash := bodyHash(resp.Body)
	prefix := normalizedBodyPrefix(resp.Body)
	for _, sample := range p.Samples {
		score := 0
		reasons := []string{}
		if sample.StatusCode == resp.StatusCode {
			score += 20
			reasons = append(reasons, "status")
		}
		if sample.ContentType != "" && contentType != "" && sample.ContentType == contentType {
			score += 15
			reasons = append(reasons, "content-type")
		}
		if sample.Hash != "" && sample.Hash == hash {
			score += 45
			reasons = append(reasons, "body-hash")
		}
		if sample.BodyPrefix != "" && sample.BodyPrefix == prefix && lengthClose(sample.Length, length, 0.35) {
			score += 30
			reasons = append(reasons, "prefix+length")
		}
		if sample.Title != "" && title != "" && strings.EqualFold(sample.Title, title) && lengthClose(sample.Length, length, 0.25) {
			score += 30
			reasons = append(reasons, "title+length")
		}
		if sample.Title == "" && title == "" && lengthClose(sample.Length, length, 0.12) {
			score += 15
			reasons = append(reasons, "blank-title+length")
		}
		if score >= 60 {
			return true, minInt(score, 100), strings.Join(reasons, ",")
		}
	}
	return false, 0, ""
}

func hasUniquePageKeywords(body []byte) bool {
	lower := strings.ToLower(safeTextPreview(body))
	for _, kw := range []string{"login", "sign in", "password", "csrf", "admin", "dashboard", "swagger", "openapi", "phpinfo()", "actuator", "grafana", "jenkins"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func looksRandomJSString(s string) bool {
	s = strings.Trim(s, "/")
	if len(s) >= 16 && regexp.MustCompile(`^[a-f0-9]{16,}$`).MatchString(strings.ToLower(s)) {
		return true
	}
	if len(s) >= 24 && regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`).MatchString(s) && !strings.Contains(s, "/") {
		return true
	}
	return false
}

func looksAPIEndpoint(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "graphql") || strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") {
		return true
	}
	for _, prefix := range []string{"/api/", "/api", "/v1/", "/v2/", "/v3/", "/auth/", "/admin/", "/oauth/", "/login", "/users", "/debug", "/actuator"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
