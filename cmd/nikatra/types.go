package main

import (
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	toolName    = "Nikatra"
	toolVersion = "1.0.0"
)

const legalBanner = `Nikatra Defensive Web Vulnerability Scanner

Legal use only: run this tool only against systems you own or are explicitly authorized to test.
Nikatra performs safe observational checks and does not exploit, brute force, bypass, evade, or damage systems.
`

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var severityRank = map[Severity]int{
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

var severityWeight = map[Severity]float64{
	SeverityInfo:     1.0,
	SeverityLow:      4.0,
	SeverityMedium:   11.0,
	SeverityHigh:     24.0,
	SeverityCritical: 42.0,
}

type Config struct {
	TargetInput        string
	Concurrency        int
	Timeout            time.Duration
	UserAgent          string
	OutputFormat       string
	OutputPath         string
	SafeMode           bool
	ScanProfile        string
	MaxRedirects       int
	RateLimit          float64
	CustomHeaders      []HeaderKV
	Cookie             string
	BearerToken        string
	BasicAuth          string
	BasicAuthUser      string
	BasicAuthPass      string
	ScanDepth          int
	MaxPages           int
	IncludeChecks      map[string]bool
	ExcludeChecks      map[string]bool
	IncludeList        []string
	ExcludeList        []string
	AllowExternal      bool
	Authorized         bool
	ResponseLimitBytes int64
	Retries            int
	FollowSitemap      bool
	FollowRobots       bool
	RespectRobots      bool
	TemplatesPath      string
	ConfigPath         string
	Verbose            bool
	SelfTest           bool
	SelfTestServer     bool
	TemplateCount      int
	RobotsPolicy       *RobotsPolicy
	BaselinePath       string
	FailOn             Severity
	FailOnSet          bool
	BaseURL            *url.URL
	SchemeDefaulted    bool
	ResolvedFromHTTP   bool
}

type HeaderKV struct {
	Name  string
	Value string
}

type HTTPStats struct {
	mu          sync.Mutex
	Started     time.Time
	Finished    time.Time
	Requests    int
	Errors      int
	BytesRead   int64
	StatusCodes map[int]int
	Methods     map[string]int
}

type HTTPStatsSnapshot struct {
	Started         string         `json:"started"`
	Finished        string         `json:"finished"`
	DurationSeconds float64        `json:"duration_seconds"`
	Requests        int            `json:"requests"`
	Errors          int            `json:"errors"`
	BytesRead       int64          `json:"bytes_read"`
	StatusCodes     map[string]int `json:"status_codes"`
	Methods         map[string]int `json:"methods"`
}

type RateLimiter struct{ ticker *time.Ticker }

type Engine struct {
	cfg     *Config
	base    *url.URL
	client  *http.Client
	stats   *HTTPStats
	limiter *RateLimiter
}

type ResponseData struct {
	URL            string      `json:"url"`
	FinalURL       string      `json:"final_url"`
	Method         string      `json:"method"`
	StatusCode     int         `json:"status_code"`
	Status         string      `json:"status"`
	Headers        http.Header `json:"headers,omitempty"`
	Body           []byte      `json:"-"`
	BodyText       string      `json:"body_preview,omitempty"`
	BodyTruncated  bool        `json:"body_truncated"`
	ContentLength  int64       `json:"content_length"`
	BytesRead      int64       `json:"bytes_read"`
	DurationMillis int64       `json:"duration_ms"`
	Error          string      `json:"error,omitempty"`
}

type Evidence struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Finding struct {
	ID             string     `json:"id"`
	CheckID        string     `json:"check_id"`
	Name           string     `json:"name"`
	Category       string     `json:"category"`
	Severity       Severity   `json:"severity"`
	Confidence     int        `json:"confidence"`
	URL            string     `json:"url"`
	Method         string     `json:"method"`
	StatusCode     int        `json:"status_code,omitempty"`
	Evidence       string     `json:"evidence"`
	EvidenceItems  []Evidence `json:"evidence_items,omitempty"`
	Description    string     `json:"description"`
	Recommendation string     `json:"recommendation"`
	BaselineStatus string     `json:"baseline_status,omitempty"`
}

type Technology struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Evidence   string `json:"evidence"`
	Confidence int    `json:"confidence"`
}

type HeaderState struct {
	Name       string `json:"name"`
	Present    bool   `json:"present"`
	Value      string `json:"value,omitempty"`
	Assessment string `json:"assessment"`
}

type TLSSummary struct {
	Enabled              bool     `json:"enabled"`
	Host                 string   `json:"host"`
	Port                 string   `json:"port,omitempty"`
	Version              string   `json:"version,omitempty"`
	CipherSuite          string   `json:"cipher_suite,omitempty"`
	CertificateSubject   string   `json:"certificate_subject,omitempty"`
	CertificateIssuer    string   `json:"certificate_issuer,omitempty"`
	SANs                 []string `json:"sans,omitempty"`
	NotBefore            string   `json:"not_before,omitempty"`
	NotAfter             string   `json:"not_after,omitempty"`
	DaysUntilExpiry      int      `json:"days_until_expiry,omitempty"`
	Expired              bool     `json:"expired"`
	NotYetValid          bool     `json:"not_yet_valid"`
	SelfSigned           bool     `json:"self_signed"`
	HostnameMismatch     bool     `json:"hostname_mismatch"`
	TrustedChain         bool     `json:"trusted_chain"`
	LegacyTLSSupported   []string `json:"legacy_tls_supported,omitempty"`
	HTTPRedirectsToHTTPS bool     `json:"http_redirects_to_https"`
	HTTPOnly             bool     `json:"http_only"`
	Error                string   `json:"error,omitempty"`
}

type RiskSummary struct {
	Score      int      `json:"score"`
	Level      Severity `json:"level"`
	TopReasons []string `json:"top_reasons"`
}

type BaselineComparison struct {
	Enabled          bool      `json:"enabled"`
	New              int       `json:"new"`
	Existing         int       `json:"existing"`
	Resolved         int       `json:"resolved"`
	ResolvedFindings []Finding `json:"resolved_findings,omitempty"`
	Error            string    `json:"error,omitempty"`
}

type ReportConfig struct {
	TargetInput         string   `json:"target_input"`
	Concurrency         int      `json:"concurrency"`
	Timeout             string   `json:"timeout"`
	UserAgent           string   `json:"user_agent"`
	OutputFormat        string   `json:"output_format"`
	SafeMode            bool     `json:"safe_mode"`
	ScanProfile         string   `json:"scan_profile"`
	MaxRedirects        int      `json:"max_redirects"`
	RateLimit           float64  `json:"rate_limit_requests_per_second"`
	ScanDepth           int      `json:"scan_depth"`
	MaxPages            int      `json:"max_pages"`
	AllowExternal       bool     `json:"allow_external"`
	FollowSitemap       bool     `json:"follow_sitemap"`
	FollowRobots        bool     `json:"follow_robots"`
	RespectRobots       bool     `json:"respect_robots"`
	TemplatesPath       string   `json:"templates,omitempty"`
	TemplateCount       int      `json:"template_count,omitempty"`
	ConfigPath          string   `json:"config_path,omitempty"`
	Verbose             bool     `json:"verbose"`
	IncludeChecks       []string `json:"include_checks,omitempty"`
	ExcludeChecks       []string `json:"exclude_checks,omitempty"`
	ResponseLimitBytes  int64    `json:"response_limit_bytes"`
	Retries             int      `json:"retries"`
	CustomHeaderNames   []string `json:"custom_header_names,omitempty"`
	CookiesSupplied     bool     `json:"cookies_supplied"`
	BearerTokenSupplied bool     `json:"bearer_token_supplied"`
	BasicAuthSupplied   bool     `json:"basic_auth_supplied"`
	BaselinePath        string   `json:"baseline_path,omitempty"`
	FailOn              string   `json:"fail_on,omitempty"`
}

type Report struct {
	Tool                    string                 `json:"tool"`
	Version                 string                 `json:"version"`
	Target                  string                 `json:"target"`
	Timestamp               string                 `json:"timestamp"`
	Config                  ReportConfig           `json:"config"`
	Technologies            []Technology           `json:"technologies"`
	Findings                []Finding              `json:"findings"`
	Risk                    RiskSummary            `json:"risk"`
	TopReasons              []string               `json:"top_reasons,omitempty"`
	CrawledURLs             []string               `json:"crawled_urls"`
	DiscoveredJSReferences  []string               `json:"discovered_js_references"`
	DiscoveredCSSReferences []string               `json:"discovered_css_references"`
	DiscoveredEndpoints     []string               `json:"discovered_endpoints"`
	HTTPStats               HTTPStatsSnapshot      `json:"http_statistics"`
	TLS                     TLSSummary             `json:"tls"`
	SecurityHeadersSummary  map[string]HeaderState `json:"security_headers_summary"`
	Baseline                BaselineComparison     `json:"baseline_comparison"`
}

type PageData struct {
	URL         string
	StatusCode  int
	Headers     http.Header
	Body        []byte
	ContentType string
	Title       string
}

type CrawlResult struct {
	Pages      []PageData
	PageURLs   []string
	JSRefs     []string
	CSSRefs    []string
	Endpoints  []string
	SourceMaps []string
}

type Soft404Profile struct{ Samples []Soft404Sample }

type Soft404Sample struct {
	URL         string
	StatusCode  int
	Title       string
	Length      int
	ContentType string
	Hash        string
	Location    string
	BodyPrefix  string
}

type PathCheck struct {
	ID                string
	Name              string
	Category          string
	Severity          Severity
	Description       string
	Recommendation    string
	Paths             []string
	Method            string
	StatusCodes       []int
	BodyRegex         []string
	HeaderRegex       map[string]string
	NegativeBodyRegex []string
	EvidenceRegex     []string
	Confidence        int
	Tags              []string
	Confirm           func(*ResponseData, *Soft404Profile) (bool, int, string)
}

type RobotsPolicy struct {
	Disallow []string
	Allow    []string
}
