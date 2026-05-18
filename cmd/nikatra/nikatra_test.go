package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunSelfTests(t *testing.T) {
	if err := RunSelfTests(); err != nil {
		t.Fatalf("self tests failed: %v", err)
	}
}

func TestBuildURLPreservesQuery(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	u := BuildURL(base, "/server-status?auto")
	if u.String() != "https://example.com/server-status?auto" {
		t.Fatalf("unexpected URL: %s", u.String())
	}
}

func TestAnalyzeHTTPMethodsGroupsFinding(t *testing.T) {
	resp := &ResponseData{URL: "https://example.com/", Method: http.MethodOptions, StatusCode: 200, Headers: http.Header{}}
	resp.Headers.Set("Allow", "GET, POST, PUT, DELETE, PATCH")
	findings := AnalyzeHTTPMethods(resp)
	if len(findings) != 1 {
		t.Fatalf("expected one grouped finding, got %d", len(findings))
	}
	if findings[0].CheckID != "risky-methods-advertised" {
		t.Fatalf("unexpected check id: %s", findings[0].CheckID)
	}
	if !strings.Contains(findings[0].Evidence, "PUT") || !strings.Contains(findings[0].Evidence, "DELETE") || !strings.Contains(findings[0].Evidence, "PATCH") {
		t.Fatalf("missing method evidence: %s", findings[0].Evidence)
	}
}

func TestSafeModeCapsAndProfileParsing(t *testing.T) {
	cfg, err := parseConfig([]string{"--self-test", "--rate-limit", "0", "--concurrency", "99", "--max-pages", "999", "--scan-profile", "standard"})
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if cfg.ScanProfile != "standard" {
		t.Fatalf("unexpected profile: %s", cfg.ScanProfile)
	}
	if cfg.Concurrency != 32 || cfg.MaxPages != 250 || cfg.RateLimit != 10 {
		t.Fatalf("safe-mode caps not applied: concurrency=%d maxPages=%d rate=%g", cfg.Concurrency, cfg.MaxPages, cfg.RateLimit)
	}
	cfg, err = parseConfig([]string{"--self-test", "--safe-mode=false", "--rate-limit", "0", "--concurrency", "99", "--max-pages", "999"})
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if cfg.RateLimit != 0 || cfg.Concurrency != 99 || cfg.MaxPages != 999 {
		t.Fatalf("safe-mode disabled should not cap: concurrency=%d maxPages=%d rate=%g", cfg.Concurrency, cfg.MaxPages, cfg.RateLimit)
	}
}

func TestBuildPathCheckProfiles(t *testing.T) {
	basic := BuildPathChecksForProfile("basic")
	standard := BuildPathChecksForProfile("standard")
	full := BuildPathChecksForProfile("full")
	if len(basic) == 0 || len(standard) <= len(basic) || len(full) <= len(standard) {
		t.Fatalf("unexpected profile sizes: basic=%d standard=%d full=%d", len(basic), len(standard), len(full))
	}
}

func TestExternalAuthHeadersAreStripped(t *testing.T) {
	base, _ := url.Parse("https://internal.example/")
	cfg := defaultConfig()
	cfg.AllowExternal = true
	cfg.CustomHeaders = []HeaderKV{{Name: "X-API-Key", Value: "secret-value"}, {Name: "X-Trace", Value: "trace-value"}}
	cfg.Cookie = "session=secret"
	cfg.BearerToken = "bearer-secret"
	cfg.BasicAuthUser = "user"
	cfg.BasicAuthPass = "pass"
	engine := NewEngine(cfg, base)
	defer engine.Close()

	sameReq, _ := http.NewRequest(http.MethodGet, "https://internal.example/app", nil)
	engine.applyHeaders(sameReq)
	if sameReq.Header.Get("Authorization") == "" || sameReq.Header.Get("Cookie") == "" || sameReq.Header.Get("X-API-Key") == "" {
		t.Fatalf("expected auth/custom headers on same-origin request: %v", sameReq.Header)
	}

	externalReq, _ := http.NewRequest(http.MethodGet, "https://external.example/app", nil)
	engine.applyHeaders(externalReq)
	for _, name := range []string{"Authorization", "Cookie", "X-API-Key", "X-Trace"} {
		if got := externalReq.Header.Get(name); got != "" {
			t.Fatalf("external request leaked %s=%q", name, got)
		}
	}
	if externalReq.Header.Get("User-Agent") == "" {
		t.Fatalf("expected non-sensitive default headers to remain")
	}
}

func TestRespectRobotsBlocksPathChecks(t *testing.T) {
	var envHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>ok</title></html>"))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nDisallow: /.env\n"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		envHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("APP_KEY=base64:test\nDB_PASSWORD=supersecret\n"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := defaultConfig()
	cfg.TargetInput = server.URL
	cfg.Authorized = true
	cfg.RespectRobots = true
	cfg.ScanProfile = "basic"
	cfg.Timeout = 2 * time.Second
	cfg.RateLimit = 0
	cfg.IncludeList = []string{"env-file"}
	cfg.IncludeChecks = map[string]bool{"env-file": true}
	cfg.ExcludeChecks = map[string]bool{}
	report, err := RunScan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}
	if envHits.Load() != 0 {
		t.Fatalf("robots-blocked .env path was requested %d times", envHits.Load())
	}
	for _, f := range report.Findings {
		if f.CheckID == "env-file" {
			t.Fatalf("robots-blocked env finding should not be present: %+v", f)
		}
	}
}

func TestFindingEvidenceRedacted(t *testing.T) {
	f := NewFinding("secret", "Secret", "Information Disclosure", SeverityHigh, 90, "https://example.com/.env?token=plainsecret", "GET", 200, "path=/.env; DB_PASSWORD=supersecret; AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF; Authorization: Bearer abcdefghijklmnop", "d", "r")
	for _, raw := range []string{"supersecret", "AKIA1234567890ABCDEF", "abcdefghijklmnop"} {
		if strings.Contains(f.Evidence, raw) {
			t.Fatalf("evidence leaked raw secret %q: %s", raw, f.Evidence)
		}
	}
	if !strings.Contains(f.Evidence, "<redacted:") {
		t.Fatalf("expected redaction marker in evidence: %s", f.Evidence)
	}
}
