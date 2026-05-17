package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

func RunSelfTestServer(ctx context.Context, cfg *Config) (*Report, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><script src="/static/app.js"></script></head><body>Nikatra test</body></html>`)
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "APP_KEY=base64:test\nDB_PASSWORD=secret\nAWS_SECRET_ACCESS_KEY=abc123secret\n")
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "[core]\nrepositoryformatversion = 0\n[remote \"origin\"]\nurl = https://example.invalid/repo.git\n")
	})
	mux.HandleFunc("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><title>phpinfo()</title><body>PHP Version 8.2 phpinfo()</body></html>")
	})
	mux.HandleFunc("/server-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "Apache Server Status for localhost")
	})
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"openapi":"3.0.0","paths":{"/api/test":{}}}`)
	})
	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "debug=true stack trace goroutine")
	})
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"propertySources":[{"name":"systemProperties"}]}`)
	})
	mux.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write([]byte{'P', 'K', 3, 4, 1, 2, 3, 4})
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<form><input type="password" name="password"><input type="hidden" name="csrf"></form>`)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `fetch('/api/v1/users'); fetch('/graphql'); //# sourceMappingURL=app.js.map`)
	})
	mux.HandleFunc("/static/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"version":3,"sources":["app.ts"],"mappings":""}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	copyCfg := *cfg
	copyCfg.TargetInput = server.URL
	copyCfg.Authorized = true
	copyCfg.Concurrency = maxInt(copyCfg.Concurrency, 16)
	copyCfg.RateLimit = 0
	copyCfg.Timeout = 3 * time.Second
	copyCfg.ScanDepth = maxInt(copyCfg.ScanDepth, 1)
	copyCfg.MaxPages = maxInt(copyCfg.MaxPages, 20)
	copyCfg.ResponseLimitBytes = maxInt64(copyCfg.ResponseLimitBytes, 1024*1024)
	copyCfg.TemplatesPath = ""
	selfTestIDs := []string{"env-file", "git-config", "phpinfo", "apache-status", "api-docs", "debug-endpoint", "spring-actuator", "backup-archive", "admin-panel"}
	copyCfg.IncludeList = selfTestIDs
	copyCfg.IncludeChecks = map[string]bool{}
	for _, id := range selfTestIDs {
		copyCfg.IncludeChecks[id] = true
	}
	copyCfg.ExcludeList = nil
	copyCfg.ExcludeChecks = map[string]bool{}
	return RunScan(ctx, &copyCfg)
}

func RunSelfTests() error {
	var failures []string
	if u, _, err := NormalizeTarget("example.com/path#frag"); err != nil || u.Scheme != "https" || u.Fragment != "" {
		failures = append(failures, "NormalizeTarget")
	}
	if sev, err := parseSeverity("high"); err != nil || sev != SeverityHigh {
		failures = append(failures, "parseSeverity")
	}
	fs := []Finding{NewFinding("a", "A", "Cat", SeverityCritical, 95, "https://e/.env", "GET", 200, "secret", "d", "r")}
	if CalculateRisk(fs).Level != SeverityCritical {
		failures = append(failures, "CalculateRisk critical")
	}
	dupes := DedupeFindings(append(fs, fs...))
	if len(dupes) != 1 {
		failures = append(failures, "DedupeFindings")
	}
	tpl := []byte(`[{"id":"x","name":"X","category":"Exposure","severity":"LOW","paths":["/x"],"method":"GET","status_codes":[200],"body_regex":["ok"],"confidence":80}]`)
	tmp, err := os.CreateTemp("", "nikatra-template-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(tpl)
	tmp.Close()
	loaded, err := LoadTemplateChecks(tmp.Name())
	if err != nil || len(loaded) != 1 {
		failures = append(failures, "LoadTemplateChecks")
	}
	robots := ParseRobotsPolicy("User-agent: *\nDisallow: /private\nAllow: /private/public\n")
	if robots.Allowed("/private/x") || !robots.Allowed("/private/public/x") {
		failures = append(failures, "ParseRobotsPolicy")
	}
	softBody := []byte("<title>Not Found</title>not found")
	prof := &Soft404Profile{Samples: []Soft404Sample{{StatusCode: 200, Title: "Not Found", Length: len(softBody), ContentType: "text/html", BodyPrefix: normalizedBodyPrefix(softBody), Hash: bodyHash(softBody)}}}
	resp := &ResponseData{StatusCode: 200, Headers: http.Header{"Content-Type": []string{"text/html"}}, Body: softBody}
	if ok, _, _ := prof.Decision(resp); !ok {
		failures = append(failures, "Soft404Profile.Decision")
	}
	rep := &Report{Tool: toolName, Version: toolVersion, Target: "https://example.com", Timestamp: time.Now().UTC().Format(time.RFC3339), Risk: CalculateRisk(nil)}
	if _, err := RenderReport(rep, "json"); err != nil {
		failures = append(failures, "RenderReport json")
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, ", "))
	}
	return nil
}
