package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (h *headerList) String() string {
	parts := make([]string, 0, len(*h))
	for _, kv := range *h {
		parts = append(parts, kv.Name+": "+kv.Value)
	}
	return strings.Join(parts, ", ")
}

func (h *headerList) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("header must be in Name: value format")
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}
	*h = append(*h, HeaderKV{Name: name, Value: value})
	return nil
}

type durationFlag struct{ value time.Duration }

func (d *durationFlag) String() string { return d.value.String() }

func (d *durationFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("duration cannot be empty")
	}
	if parsed, err := time.ParseDuration(s); err == nil {
		d.value = parsed
		return nil
	}
	seconds, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid duration %q; use values like 10s, 1500ms, or 10", s)
	}
	if seconds <= 0 {
		return errors.New("duration must be positive")
	}
	d.value = time.Duration(seconds * float64(time.Second))
	return nil
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprint(os.Stderr, legalBanner)

	if cfg.SelfTest {
		if err := RunSelfTests(); err != nil {
			fmt.Fprintf(os.Stderr, "SELF-TEST FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "SELF-TEST PASS")
		return
	}

	if cfg.SelfTestServer {
		cfg.Authorized = true
		report, err := RunSelfTestServer(context.Background(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "self-test server scan failed: %v\n", err)
			os.Exit(1)
		}
		output, err := RenderReport(report, cfg.OutputFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
			os.Exit(1)
		}
		if cfg.OutputPath != "" {
			if err := os.WriteFile(cfg.OutputPath, []byte(output), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "could not write output file: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Print(output)
		}
		if cfg.FailOnSet && hasFindingAtOrAbove(report.Findings, cfg.FailOn) {
			os.Exit(3)
		}
		return
	}

	if !cfg.Authorized {
		fmt.Fprintln(os.Stderr, "WARNING: --authorized is required. Nikatra only scans systems you own or are explicitly authorized to test.")
		os.Exit(2)
	}
	if strings.TrimSpace(cfg.TargetInput) == "" {
		fmt.Fprintln(os.Stderr, "target URL is required. Provide it as --target https://example.com or as the first positional argument.")
		os.Exit(2)
	}
	verbosef(cfg, "scan starting for target %s", cfg.TargetInput)
	report, err := RunScan(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	output, err := RenderReport(report, cfg.OutputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
		os.Exit(1)
	}
	if cfg.OutputPath != "" {
		if err := os.WriteFile(cfg.OutputPath, []byte(output), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "could not write output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(output)
	}
	if cfg.FailOnSet && hasFindingAtOrAbove(report.Findings, cfg.FailOn) {
		os.Exit(3)
	}
}

func defaultConfig() *Config {
	return &Config{
		Concurrency:        12,
		Timeout:            10 * time.Second,
		UserAgent:          "Nikatra/1.0 Defensive Scanner (+authorized audit)",
		OutputFormat:       "text",
		SafeMode:           true,
		MaxRedirects:       5,
		RateLimit:          5.0,
		ScanDepth:          1,
		MaxPages:           40,
		ResponseLimitBytes: 1024 * 1024,
		Retries:            1,
		IncludeChecks:      map[string]bool{},
		ExcludeChecks:      map[string]bool{},
	}
}

func parseConfig(args []string) (*Config, error) {
	configPath := findFlagValue(args, "config")
	cfg := defaultConfig()
	if configPath != "" {
		if err := LoadConfigFile(configPath, cfg); err != nil {
			return nil, err
		}
		cfg.ConfigPath = configPath
	}

	fs := flag.NewFlagSet("nikatra", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	timeout := &durationFlag{value: cfg.Timeout}
	headers := headerList(append([]HeaderKV(nil), cfg.CustomHeaders...))
	includeRaw := strings.Join(cfg.IncludeList, ",")
	excludeRaw := strings.Join(cfg.ExcludeList, ",")
	failOnRaw := ""
	if cfg.FailOnSet {
		failOnRaw = string(cfg.FailOn)
	}
	fs.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "optional JSON config file path")
	fs.StringVar(&cfg.TargetInput, "target", cfg.TargetInput, "target URL")
	fs.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "concurrent worker count")
	fs.Var(timeout, "timeout", "request timeout, e.g. 10s or 10")
	fs.StringVar(&cfg.UserAgent, "user-agent", cfg.UserAgent, "custom User-Agent")
	fs.StringVar(&cfg.OutputFormat, "format", cfg.OutputFormat, "output format: text, json, html, markdown, sarif")
	fs.StringVar(&cfg.OutputFormat, "output-format", cfg.OutputFormat, "output format: text, json, html, markdown, sarif")
	fs.StringVar(&cfg.OutputPath, "output", cfg.OutputPath, "output file path")
	fs.BoolVar(&cfg.SafeMode, "safe-mode", cfg.SafeMode, "safe mode; only observational checks and safe HTTP methods")
	fs.IntVar(&cfg.MaxRedirects, "max-redirects", cfg.MaxRedirects, "maximum redirects to follow")
	fs.Float64Var(&cfg.RateLimit, "rate-limit", cfg.RateLimit, "maximum requests per second; 0 disables rate limiting")
	fs.Var(&headers, "H", "custom header in Name: value format; may be repeated")
	fs.Var(&headers, "header", "custom header in Name: value format; may be repeated")
	fs.StringVar(&cfg.Cookie, "cookie", cfg.Cookie, "Cookie header value")
	fs.StringVar(&cfg.BearerToken, "bearer-token", cfg.BearerToken, "Bearer token for authorized scanning")
	fs.StringVar(&cfg.BasicAuth, "basic-auth", cfg.BasicAuth, "basic auth credentials in user:pass format")
	fs.IntVar(&cfg.ScanDepth, "depth", cfg.ScanDepth, "same-origin crawl depth")
	fs.IntVar(&cfg.MaxPages, "max-pages", cfg.MaxPages, "maximum pages to crawl")
	fs.StringVar(&includeRaw, "include", includeRaw, "comma-separated check IDs to include")
	fs.StringVar(&excludeRaw, "exclude", excludeRaw, "comma-separated check IDs to exclude")
	fs.BoolVar(&cfg.AllowExternal, "allow-external", cfg.AllowExternal, "allow crawling/scanning external linked origins")
	fs.BoolVar(&cfg.Authorized, "authorized", cfg.Authorized, "confirm you are authorized to scan the target")
	fs.Int64Var(&cfg.ResponseLimitBytes, "response-limit", cfg.ResponseLimitBytes, "maximum response body bytes to read per request")
	fs.IntVar(&cfg.Retries, "retries", cfg.Retries, "retry count for transient request failures")
	fs.BoolVar(&cfg.FollowSitemap, "follow-sitemap", cfg.FollowSitemap, "safely read same-origin sitemap.xml links")
	fs.BoolVar(&cfg.FollowRobots, "follow-robots", cfg.FollowRobots, "safely read same-origin robots.txt references")
	fs.BoolVar(&cfg.RespectRobots, "respect-robots", cfg.RespectRobots, "respect User-agent: * Disallow rules when crawling")
	fs.StringVar(&cfg.TemplatesPath, "templates", cfg.TemplatesPath, "optional JSON template file or directory")
	fs.StringVar(&cfg.BaselinePath, "baseline", cfg.BaselinePath, "previous JSON report for baseline comparison")
	fs.StringVar(&failOnRaw, "fail-on", failOnRaw, "CI failure threshold severity: info, low, medium, high, critical")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "write phase progress and skip details to stderr")
	fs.BoolVar(&cfg.SelfTest, "self-test", cfg.SelfTest, "run built-in unit-style checks and exit")
	fs.BoolVar(&cfg.SelfTestServer, "self-test-server", cfg.SelfTestServer, "start a local test server and scan it")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if cfg.TargetInput == "" && fs.NArg() > 0 {
		cfg.TargetInput = fs.Arg(0)
	}
	cfg.Timeout = timeout.value
	cfg.CustomHeaders = headers
	cfg.OutputFormat = strings.ToLower(strings.TrimSpace(cfg.OutputFormat))
	if cfg.OutputFormat == "md" {
		cfg.OutputFormat = "markdown"
	}
	switch cfg.OutputFormat {
	case "text", "json", "html", "markdown", "sarif":
	default:
		return nil, fmt.Errorf("unsupported output format %q", cfg.OutputFormat)
	}
	if cfg.BasicAuth != "" {
		user, pass, ok := strings.Cut(cfg.BasicAuth, ":")
		if !ok {
			return nil, errors.New("--basic-auth must be in user:pass format")
		}
		cfg.BasicAuthUser = user
		cfg.BasicAuthPass = pass
	}
	if failOnRaw != "" {
		sev, err := parseSeverity(failOnRaw)
		if err != nil {
			return nil, err
		}
		cfg.FailOn = sev
		cfg.FailOnSet = true
	}
	cfg.Concurrency = clampInt(cfg.Concurrency, 1, 128)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	cfg.ScanDepth = clampInt(cfg.ScanDepth, 0, 5)
	cfg.MaxPages = clampInt(cfg.MaxPages, 1, 1000)
	if cfg.ResponseLimitBytes < 4096 {
		cfg.ResponseLimitBytes = 4096
	}
	if cfg.ResponseLimitBytes > 10*1024*1024 {
		cfg.ResponseLimitBytes = 10 * 1024 * 1024
	}
	cfg.Retries = clampInt(cfg.Retries, 0, 5)
	if cfg.RateLimit < 0 {
		cfg.RateLimit = 0
	}
	cfg.IncludeList, cfg.IncludeChecks = parseCheckList(includeRaw)
	cfg.ExcludeList, cfg.ExcludeChecks = parseCheckList(excludeRaw)
	return cfg, nil
}

func parseCheckList(raw string) ([]string, map[string]bool) {
	out := []string{}
	set := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.ToLower(strings.TrimSpace(part))
		if id == "" || set[id] {
			continue
		}
		out = append(out, id)
		set[id] = true
	}
	sort.Strings(out)
	return out, set
}

func parseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return SeverityInfo, nil
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM", "MODERATE":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity %q", s)
	}
}
