package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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
