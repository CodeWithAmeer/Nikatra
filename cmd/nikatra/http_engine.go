package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func NewHTTPStats() *HTTPStats {
	return &HTTPStats{Started: time.Now().UTC(), StatusCodes: map[int]int{}, Methods: map[string]int{}}
}

func (s *HTTPStats) RecordRequest(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests++
	s.Methods[method]++
}

func (s *HTTPStats) RecordResponse(status int, bytesRead int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StatusCodes[status]++
	s.BytesRead += bytesRead
}

func (s *HTTPStats) RecordError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Errors++
}

func (s *HTTPStats) Finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Finished.IsZero() {
		s.Finished = time.Now().UTC()
	}
}

func (s *HTTPStats) Snapshot() HTTPStatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	finished := s.Finished
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	statusCodes := map[string]int{}
	for k, v := range s.StatusCodes {
		statusCodes[strconv.Itoa(k)] = v
	}
	methods := map[string]int{}
	for k, v := range s.Methods {
		methods[k] = v
	}
	return HTTPStatsSnapshot{
		Started:         s.Started.Format(time.RFC3339),
		Finished:        finished.Format(time.RFC3339),
		DurationSeconds: finished.Sub(s.Started).Seconds(),
		Requests:        s.Requests,
		Errors:          s.Errors,
		BytesRead:       s.BytesRead,
		StatusCodes:     statusCodes,
		Methods:         methods,
	}
}

func NewRateLimiter(rate float64) *RateLimiter {
	if rate <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	return &RateLimiter{ticker: time.NewTicker(interval)}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.ticker == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ticker.C:
		return nil
	}
}

func (r *RateLimiter) Stop() {
	if r != nil && r.ticker != nil {
		r.ticker.Stop()
	}
}

func NewEngine(cfg *Config, base *url.URL) *Engine {
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          maxInt(2, cfg.Concurrency*2),
		MaxIdleConnsPerHost:   maxInt(1, cfg.Concurrency),
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.MaxRedirects >= 0 && len(via) >= cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			if !cfg.AllowExternal && base != nil && !sameHost(req.URL, base) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Engine{cfg: cfg, base: base, client: client, stats: NewHTTPStats(), limiter: NewRateLimiter(cfg.RateLimit)}
}

func (e *Engine) Close() {
	if e.limiter != nil {
		e.limiter.Stop()
	}
	e.stats.Finish()
}

func (e *Engine) Fetch(ctx context.Context, method string, u *url.URL) (*ResponseData, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if !isAllowedRequestMethod(method) {
		return nil, fmt.Errorf("method %s is not allowed by Nikatra safe request policy", method)
	}
	if u == nil {
		return nil, errors.New("nil URL")
	}
	if !e.cfg.AllowExternal && e.base != nil && !sameHost(u, e.base) {
		return nil, fmt.Errorf("external host blocked by default policy: %s", u.Host)
	}
	retries := e.cfg.Retries
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(200*attempt) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		reqCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, method, u.String(), nil)
		if err != nil {
			cancel()
			return nil, err
		}
		e.applyHeaders(req)
		start := time.Now()
		e.stats.RecordRequest(method)
		resp, err := e.client.Do(req)
		if err != nil {
			cancel()
			e.stats.RecordError()
			lastErr = err
			continue
		}
		data := &ResponseData{
			URL:            u.String(),
			FinalURL:       resp.Request.URL.String(),
			Method:         method,
			StatusCode:     resp.StatusCode,
			Status:         resp.Status,
			Headers:        resp.Header.Clone(),
			ContentLength:  resp.ContentLength,
			DurationMillis: time.Since(start).Milliseconds(),
		}
		if resp.Body != nil {
			limit := e.cfg.ResponseLimitBytes
			if limit <= 0 {
				limit = 1024 * 1024
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
			closeErr := resp.Body.Close()
			if readErr != nil {
				err = readErr
			} else if closeErr != nil {
				err = closeErr
			}
			if int64(len(body)) > limit {
				body = body[:limit]
				data.BodyTruncated = true
			}
			data.Body = body
			data.BodyText = truncateString(safeTextPreview(body), 512)
			data.BytesRead = int64(len(body))
		}
		cancel()
		e.stats.RecordResponse(resp.StatusCode, data.BytesRead)
		if err != nil {
			e.stats.RecordError()
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 && attempt < retries {
			lastErr = fmt.Errorf("server returned %s", resp.Status)
			continue
		}
		return data, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

func (e *Engine) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", e.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,application/json,text/plain,application/javascript,text/javascript,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")
	for _, kv := range e.cfg.CustomHeaders {
		req.Header.Set(kv.Name, kv.Value)
	}
	if e.cfg.Cookie != "" && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", e.cfg.Cookie)
	}
	if e.cfg.BearerToken != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.BearerToken)
	}
	if e.cfg.BasicAuthUser != "" || e.cfg.BasicAuthPass != "" {
		req.SetBasicAuth(e.cfg.BasicAuthUser, e.cfg.BasicAuthPass)
	}
}

func isAllowedRequestMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func RunScan(ctx context.Context, cfg *Config) (*Report, error) {
	baseURL, defaulted, err := NormalizeTarget(cfg.TargetInput)
	if err != nil {
		return nil, err
	}
	cfg.SchemeDefaulted = defaulted
	if defaulted {
		resolved := ResolveDefaultScheme(ctx, cfg, baseURL)
		if resolved.Scheme == "http" {
			cfg.ResolvedFromHTTP = true
		}
		baseURL = resolved
	}
	cfg.BaseURL = baseURL
	engine := NewEngine(cfg, baseURL)
	defer engine.Close()
	verbosef(cfg, "normalized target: %s", baseURL.String())
	var findings []Finding
	tlsSummary, tlsFindings := CheckTLS(ctx, cfg, baseURL)
	findings = append(findings, tlsFindings...)
	redirectsHTTPS := CheckHTTPToHTTPSRedirect(ctx, cfg, baseURL)
	tlsSummary.HTTPRedirectsToHTTPS = redirectsHTTPS
	if baseURL.Scheme == "http" {
		tlsSummary.HTTPOnly = true
		findings = append(findings, NewFinding("http-only", "Target is using HTTP", "TLS", SeverityMedium, 95, baseURL.String(), "HEAD", 0, "Target URL scheme is http:// and HTTPS was not selected for this scan.", "The target was scanned over plain HTTP, which exposes traffic to interception and tampering.", "Serve the application over HTTPS and redirect HTTP requests to HTTPS."))
	} else if !redirectsHTTPS {
		findings = append(findings, NewFinding("missing-http-to-https-redirect", "HTTP does not clearly redirect to HTTPS", "TLS", SeverityLow, 70, "http://"+baseURL.Host+"/", "HEAD", 0, "No same-host HTTP 3xx redirect to https:// was observed.", "The HTTP endpoint did not clearly redirect to HTTPS during the safe redirect check.", "Configure the HTTP virtual host or proxy to redirect all traffic to HTTPS."))
	}
	root := RootURL(baseURL)
	rootResp, rootErr := engine.Fetch(ctx, http.MethodGet, root)
	if rootErr != nil {
		findings = append(findings, NewFinding("target-request-failed", "Target request failed", "Connectivity", SeverityMedium, 90, root.String(), http.MethodGet, 0, truncateString(rootErr.Error(), 240), "Nikatra could not retrieve the target root page.", "Verify the target URL, network path, TLS configuration, and authorization scope before scanning again."))
	}
	var securityHeaderSummary map[string]HeaderState
	var crawlRes CrawlResult
	var technologies []Technology
	if rootResp != nil {
		if cfg.RespectRobots {
			cfg.RobotsPolicy = LoadRobotsPolicy(ctx, engine, baseURL, cfg)
		}
		headerFindings, summary := AnalyzeSecurityHeaders(rootResp, baseURL)
		securityHeaderSummary = summary
		findings = append(findings, headerFindings...)
		if optionsResp, err := engine.Fetch(ctx, http.MethodOptions, root); err == nil && optionsResp != nil {
			findings = append(findings, AnalyzeHTTPMethods(optionsResp)...)
		}
		soft404 := CalibrateSoft404(ctx, engine, baseURL)
		verbosef(cfg, "soft-404 samples collected: %d", len(soft404.Samples))
		crawlRes = Crawl(ctx, engine, baseURL, rootResp, cfg)
		verbosef(cfg, "crawler pages=%d js=%d css=%d endpoints=%d", len(crawlRes.PageURLs), len(crawlRes.JSRefs), len(crawlRes.CSSRefs), len(crawlRes.Endpoints))
		technologies = EnhanceFingerprinting(Fingerprint(rootResp, crawlRes.Pages), rootResp, crawlRes.Pages)
		findings = append(findings, TechnologyVersionFindings(technologies, rootResp.URL)...)
		findings = append(findings, AnalyzePages(crawlRes.Pages, baseURL)...)
		findings = append(findings, AnalyzeSensitivePageCaching(crawlRes.Pages)...)
		pathFindings := RunPathChecks(ctx, engine, baseURL, cfg, soft404)
		findings = append(findings, pathFindings...)
		findings = append(findings, AnalyzeDiscoveredAssets(ctx, engine, baseURL, cfg, crawlRes, soft404)...)
	} else {
		securityHeaderSummary = map[string]HeaderState{}
	}
	findings = DedupeFindings(findings)
	SortFindings(findings)
	baseline := ApplyBaseline(cfg.BaselinePath, findings)
	risk := CalculateRisk(findings)
	return &Report{
		Tool:                    toolName,
		Version:                 toolVersion,
		Target:                  baseURL.String(),
		Timestamp:               time.Now().UTC().Format(time.RFC3339),
		Config:                  BuildReportConfig(cfg),
		Technologies:            technologies,
		Findings:                findings,
		Risk:                    risk,
		TopReasons:              risk.TopReasons,
		CrawledURLs:             crawlRes.PageURLs,
		DiscoveredJSReferences:  crawlRes.JSRefs,
		DiscoveredCSSReferences: crawlRes.CSSRefs,
		DiscoveredEndpoints:     crawlRes.Endpoints,
		HTTPStats:               engine.stats.Snapshot(),
		TLS:                     tlsSummary,
		SecurityHeadersSummary:  securityHeaderSummary,
		Baseline:                baseline,
	}, nil
}

func CalibrateSoft404(ctx context.Context, engine *Engine, base *url.URL) *Soft404Profile {
	profile := &Soft404Profile{}
	for i := 0; i < 4; i++ {
		token := randomToken(8)
		paths := []string{"/nikatra-not-found-check-" + token, "/" + token + "/definitely-not-present", "/assets/" + token + ".txt", "/api/" + token}
		u := BuildURL(base, paths[i%len(paths)])
		resp, err := engine.Fetch(ctx, http.MethodGet, u)
		if err != nil || resp == nil {
			continue
		}
		profile.Samples = append(profile.Samples, Soft404Sample{URL: resp.FinalURL, StatusCode: resp.StatusCode, Title: extractTitle(resp.Body), Length: len(resp.Body), ContentType: firstHeaderToken(resp.Headers.Get("Content-Type")), Hash: bodyHash(resp.Body), Location: resp.Headers.Get("Location"), BodyPrefix: normalizedBodyPrefix(resp.Body)})
	}
	return profile
}

func Crawl(ctx context.Context, engine *Engine, base *url.URL, root *ResponseData, cfg *Config) CrawlResult {
	visited := map[string]bool{}
	queued := map[string]bool{}
	jsSet, cssSet, endpointSet, sourceMapSet := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	var pages []PageData
	rootURL := RootURL(base)
	rootKey := normalizedURLKey(rootURL)
	visited[rootKey] = true
	if root != nil {
		pages = append(pages, pageFromResponse(root))
		collectAssets(root.Body, rootURL, base, cfg, jsSet, cssSet)
	}
	current := []*url.URL{rootURL}
	if cfg.FollowRobots {
		for _, u := range DiscoverFromRobots(ctx, engine, base, cfg) {
			key := normalizedURLKey(u)
			if !visited[key] && !queued[key] && !shouldSkipCrawlerCandidate(cfg, u) {
				current = append(current, u)
				queued[key] = true
			}
		}
	}
	if cfg.FollowSitemap {
		for _, u := range DiscoverFromSitemap(ctx, engine, base, cfg, BuildURL(base, "/sitemap.xml"), 0) {
			key := normalizedURLKey(u)
			if !visited[key] && !queued[key] && !shouldSkipCrawlerCandidate(cfg, u) {
				current = append(current, u)
				queued[key] = true
			}
		}
	}
	for depth := 0; depth <= cfg.ScanDepth && len(current) > 0 && len(pages) < cfg.MaxPages; depth++ {
		var candidates []*url.URL
		for _, cu := range current {
			key := normalizedURLKey(cu)
			if depth == 0 && key == rootKey {
				if root != nil {
					for _, link := range ExtractLinks(root.Body, cu, base, cfg.AllowExternal) {
						if len(pages)+len(candidates) >= cfg.MaxPages {
							break
						}
						lk := normalizedURLKey(link)
						if visited[lk] || queued[lk] || shouldSkipCrawlerCandidate(cfg, link) {
							continue
						}
						queued[lk] = true
						candidates = append(candidates, link)
					}
				}
				continue
			}
			if visited[key] || shouldSkipCrawlerCandidate(cfg, cu) {
				continue
			}
			candidates = append(candidates, cu)
		}
		if len(candidates) == 0 {
			break
		}
		results := crawlFetchBatch(ctx, engine, candidates, cfg.Concurrency)
		var next []*url.URL
		for _, result := range results {
			if result.Response == nil || result.Error != nil {
				continue
			}
			visited[normalizedURLKey(result.ResponseURL)] = true
			page := pageFromResponse(result.Response)
			if !isHTMLLike(page.ContentType) && !looksLikeHTML(page.Body) {
				continue
			}
			pages = append(pages, page)
			collectAssets(result.Response.Body, result.ResponseURL, base, cfg, jsSet, cssSet)
			if len(pages) >= cfg.MaxPages {
				break
			}
			for _, link := range ExtractLinks(result.Response.Body, result.ResponseURL, base, cfg.AllowExternal) {
				if len(pages)+len(next) >= cfg.MaxPages {
					break
				}
				key := normalizedURLKey(link)
				if visited[key] || queued[key] || shouldSkipCrawlerCandidate(cfg, link) {
					continue
				}
				queued[key] = true
				next = append(next, link)
			}
		}
		current = next
	}
	jsRefs := sortedSet(jsSet)
	cssRefs := sortedSet(cssSet)
	FetchJSDiscoveries(ctx, engine, base, cfg, jsRefs, endpointSet, sourceMapSet)
	pageURLs := pageURLs(pages)
	return CrawlResult{Pages: pages, PageURLs: pageURLs, JSRefs: jsRefs, CSSRefs: cssRefs, Endpoints: sortedSet(endpointSet), SourceMaps: sortedSet(sourceMapSet)}
}

func crawlFetchBatch(ctx context.Context, engine *Engine, urls []*url.URL, concurrency int) []crawlResult {
	if len(urls) == 0 {
		return nil
	}
	concurrency = clampInt(concurrency, 1, len(urls))
	tasks := make(chan *url.URL)
	results := make(chan crawlResult, len(urls))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range tasks {
				resp, err := engine.Fetch(ctx, http.MethodGet, u)
				results <- crawlResult{Response: resp, ResponseURL: u, Error: err}
			}
		}()
	}
	for _, u := range urls {
		tasks <- u
	}
	close(tasks)
	wg.Wait()
	close(results)
	out := make([]crawlResult, 0, len(urls))
	for r := range results {
		out = append(out, r)
	}
	return out
}

func FetchJSDiscoveries(ctx context.Context, engine *Engine, base *url.URL, cfg *Config, jsRefs []string, endpointSet, sourceMapSet map[string]bool) {
	maxJS := minInt(len(jsRefs), 30)
	for i := 0; i < maxJS; i++ {
		u, err := url.Parse(jsRefs[i])
		if err != nil || (!cfg.AllowExternal && !sameHost(u, base)) {
			continue
		}
		resp, err := engine.Fetch(ctx, http.MethodGet, u)
		if err != nil || resp == nil || resp.StatusCode >= 400 || !isJavaScriptLike(firstHeaderToken(resp.Headers.Get("Content-Type")), resp.Body) {
			continue
		}
		for _, ep := range ExtractJSEndpoints(resp.Body, u, base, cfg.AllowExternal) {
			endpointSet[ep] = true
		}
		for _, sm := range ExtractSourceMapRefs(resp.Body, u, base, cfg.AllowExternal) {
			sourceMapSet[sm] = true
		}
	}
}

func DiscoverFromRobots(ctx context.Context, engine *Engine, base *url.URL, cfg *Config) []*url.URL {
	resp, err := engine.Fetch(ctx, http.MethodGet, BuildURL(base, "/robots.txt"))
	if err != nil || resp == nil || resp.StatusCode >= 400 || len(resp.Body) == 0 || len(resp.Body) > 256*1024 {
		return nil
	}
	var urls []*url.URL
	for _, line := range strings.Split(string(resp.Body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key != "sitemap" && key != "disallow" && key != "allow" {
			continue
		}
		if val == "" || val == "/" || strings.Contains(val, "*") {
			continue
		}
		u := resolveLink(val, RootURL(base))
		if u == nil || (!cfg.AllowExternal && !sameHost(u, base)) {
			continue
		}
		urls = append(urls, u)
		if len(urls) >= 100 {
			break
		}
	}
	return urls
}

func DiscoverFromSitemap(ctx context.Context, engine *Engine, base *url.URL, cfg *Config, sitemap *url.URL, depth int) []*url.URL {
	if sitemap == nil || depth > 2 || (!cfg.AllowExternal && !sameHost(sitemap, base)) {
		return nil
	}
	resp, err := engine.Fetch(ctx, http.MethodGet, sitemap)
	if err != nil || resp == nil || resp.StatusCode >= 400 || len(resp.Body) == 0 || len(resp.Body) > 2*1024*1024 {
		return nil
	}
	var parsed sitemapURLSet
	if err := xml.Unmarshal(resp.Body, &parsed); err != nil {
		return nil
	}
	var urls []*url.URL
	for _, item := range parsed.URLs {
		u := resolveLink(strings.TrimSpace(item.Loc), RootURL(base))
		if u == nil || (!cfg.AllowExternal && !sameHost(u, base)) {
			continue
		}
		urls = append(urls, u)
		if len(urls) >= cfg.MaxPages {
			return urls
		}
	}
	for _, sm := range parsed.Sitemaps {
		u := resolveLink(strings.TrimSpace(sm.Loc), RootURL(base))
		if u == nil || (!cfg.AllowExternal && !sameHost(u, base)) {
			continue
		}
		urls = append(urls, DiscoverFromSitemap(ctx, engine, base, cfg, u, depth+1)...)
		if len(urls) >= cfg.MaxPages {
			return urls[:cfg.MaxPages]
		}
	}
	return urls
}

func RunPathChecks(ctx context.Context, engine *Engine, base *url.URL, cfg *Config, soft404 *Soft404Profile) []Finding {
	checks := BuildPathChecks()
	external, err := LoadTemplateChecks(cfg.TemplatesPath)
	if err != nil {
		verbosef(cfg, "template load warning: %v", err)
	} else if len(external) > 0 {
		checks = append(checks, external...)
		cfg.TemplateCount = len(external)
		verbosef(cfg, "loaded %d external template checks", len(external))
	}
	var tasks []struct {
		Check PathCheck
		URL   *url.URL
		Path  string
	}
	for _, check := range checks {
		if !checkEnabled(cfg, check.ID) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(check.Method))
		if method == "" {
			method = http.MethodGet
		}
		if !isAllowedRequestMethod(method) {
			verbosef(cfg, "skipping unsafe template/check method for %s: %s", check.ID, method)
			continue
		}
		check.Method = method
		for _, p := range check.Paths {
			tasks = append(tasks, struct {
				Check PathCheck
				URL   *url.URL
				Path  string
			}{check, BuildURL(base, p), p})
		}
	}
	if len(tasks) == 0 {
		return nil
	}
	verbosef(cfg, "path/template checks queued: %d", len(tasks))
	concurrency := clampInt(cfg.Concurrency, 1, len(tasks))
	taskCh := make(chan struct {
		Check PathCheck
		URL   *url.URL
		Path  string
	})
	findCh := make(chan Finding, len(tasks))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				resp, err := engine.Fetch(ctx, task.Check.Method, task.URL)
				if err != nil || resp == nil {
					continue
				}
				if ok, score, reason := soft404.Decision(resp); ok {
					verbosef(cfg, "skipped likely soft-404 path=%s score=%d reason=%s", task.Path, score, reason)
				}
				ok, confidence, evidence := confirmPathCheck(task.Check, resp, soft404)
				if !ok {
					continue
				}
				if confidence <= 0 {
					confidence = task.Check.Confidence
				}
				if confidence <= 0 {
					confidence = 70
				}
				if evidence != "" {
					evidence = fmt.Sprintf("path=%s; status=%d; %s", task.Path, resp.StatusCode, evidence)
				} else {
					evidence = fmt.Sprintf("path=%s; status=%d", task.Path, resp.StatusCode)
				}
				findCh <- NewFinding(task.Check.ID, task.Check.Name, task.Check.Category, task.Check.Severity, confidence, resp.FinalURL, task.Check.Method, resp.StatusCode, evidence, task.Check.Description, task.Check.Recommendation)
			}
		}()
	}
	for _, task := range tasks {
		taskCh <- task
	}
	close(taskCh)
	wg.Wait()
	close(findCh)
	var findings []Finding
	for f := range findCh {
		findings = append(findings, f)
	}
	return findings
}

func AnalyzeDiscoveredAssets(ctx context.Context, engine *Engine, base *url.URL, cfg *Config, crawl CrawlResult, soft *Soft404Profile) []Finding {
	var findings []Finding
	for _, sm := range crawl.SourceMaps {
		u, err := url.Parse(sm)
		if err != nil || (!cfg.AllowExternal && !sameHost(u, base)) {
			continue
		}
		resp, err := engine.Fetch(ctx, http.MethodGet, u)
		if err != nil || resp == nil || !responseUsable(resp, soft) {
			continue
		}
		if strings.Contains(strings.ToLower(string(firstN(resp.Body, 2048))), "\"sources\"") && strings.Contains(strings.ToLower(string(firstN(resp.Body, 2048))), "\"mappings\"") {
			findings = append(findings, NewFinding("source-map-exposed", "Source map file exposed", "Information Disclosure", SeverityMedium, 90, resp.FinalURL, "GET", resp.StatusCode, "Source map JSON markers sources and mappings detected.", "A source map file appears publicly accessible and may reveal original source paths or code comments.", "Remove production source maps or ensure they contain no sensitive source code or comments."))
		}
	}
	return findings
}

func LoadRobotsPolicy(ctx context.Context, engine *Engine, base *url.URL, cfg *Config) *RobotsPolicy {
	policy := &RobotsPolicy{}
	resp, err := engine.Fetch(ctx, http.MethodGet, BuildURL(base, "/robots.txt"))
	if err != nil || resp == nil || resp.StatusCode >= 400 || len(resp.Body) == 0 || len(resp.Body) > 256*1024 {
		verbosef(cfg, "robots policy: no usable robots.txt")
		return policy
	}
	policy = ParseRobotsPolicy(string(resp.Body))
	verbosef(cfg, "robots policy loaded: disallow=%d allow=%d", len(policy.Disallow), len(policy.Allow))
	return policy
}
