package main

import (
	"net/url"
	"regexp"
	"strings"
)

type crawlResult struct {
	Response    *ResponseData
	ResponseURL *url.URL
	Error       error
}

func pageFromResponse(resp *ResponseData) PageData {
	return PageData{URL: resp.FinalURL, StatusCode: resp.StatusCode, Headers: resp.Headers.Clone(), Body: resp.Body, ContentType: firstHeaderToken(resp.Headers.Get("Content-Type")), Title: extractTitle(resp.Body)}
}

func pageURLs(pages []PageData) []string {
	set := map[string]bool{}
	for _, p := range pages {
		if p.URL != "" {
			set[p.URL] = true
		}
	}
	return sortedSet(set)
}

func ExtractLinks(body []byte, current, base *url.URL, allowExternal bool) []*url.URL {
	var out []*url.URL
	seen := map[string]bool{}
	s := string(body)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']([^"'#<>\s]+)["']`),
		regexp.MustCompile(`(?i)\burl\(([^)]+)\)`),
	}
	for _, re := range patterns {
		for _, m := range re.FindAllStringSubmatch(s, 1500) {
			if len(m) < 2 {
				continue
			}
			raw := strings.Trim(m[1], `"' \t\r\n`)
			u := resolveLink(raw, current)
			if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			u.Fragment = ""
			u.Path = cleanURLPath(u.Path)
			if !allowExternal && !sameHost(u, base) {
				continue
			}
			key := normalizedURLKey(u)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, u)
		}
	}
	return out
}

func resolveLink(raw string, current *url.URL) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(strings.ToLower(raw), "mailto:") || strings.HasPrefix(strings.ToLower(raw), "tel:") || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return current.ResolveReference(parsed)
}

func collectAssets(body []byte, current, base *url.URL, cfg *Config, jsSet, cssSet map[string]bool) {
	for _, link := range ExtractLinks(body, current, base, cfg.AllowExternal) {
		path := strings.ToLower(link.Path)
		if strings.HasSuffix(path, ".js") || strings.Contains(path, ".js?") {
			jsSet[link.String()] = true
		}
		if strings.HasSuffix(path, ".css") || strings.Contains(path, ".css?") {
			cssSet[link.String()] = true
		}
	}
}

func ExtractJSEndpoints(body []byte, current, base *url.URL, allowExternal bool) []string {
	s := string(body)
	re := regexp.MustCompile("(?i)[\"'`]((?:/[A-Za-z0-9_./{}?=&:%-]{2,})|(?:https?://[^\"'`\\s<>]+))[\"'`]")
	set := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(s, 1500) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.Contains(raw, " ") || strings.HasPrefix(raw, "//") || looksStaticPath(raw) || looksRandomJSString(raw) {
			continue
		}
		if !looksAPIEndpoint(raw) {
			continue
		}
		u := resolveLink(raw, current)
		if u == nil {
			continue
		}
		if !allowExternal && !sameHost(u, base) {
			continue
		}
		u.Fragment = ""
		set[u.String()] = true
	}
	return sortedSet(set)
}

func ExtractSourceMapRefs(body []byte, current, base *url.URL, allowExternal bool) []string {
	s := string(body)
	re := regexp.MustCompile(`(?m)sourceMappingURL=([^\s]+)`)
	set := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(s, 100) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "data:") {
			continue
		}
		u := resolveLink(raw, current)
		if u == nil || (!allowExternal && !sameHost(u, base)) {
			continue
		}
		set[u.String()] = true
	}
	return sortedSet(set)
}

func shouldSkipCrawlURL(u *url.URL) bool {
	if u == nil {
		return true
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return true
	}
	p := strings.ToLower(u.Path)
	if p == "" || p == "/" {
		return false
	}
	if looksStaticPath(p) {
		return true
	}
	if strings.Contains(p, "/logout") || strings.Contains(p, "/signout") || strings.Contains(p, "/delete") {
		return true
	}
	return false
}

func isHTMLLike(ct string) bool {
	ct = strings.ToLower(ct)
	return ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

func isJavaScriptLike(ct string, body []byte) bool {
	ct = strings.ToLower(ct)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.Contains(ct, "text/plain") {
		return true
	}
	s := strings.TrimSpace(string(body))
	return strings.Contains(s, "function") || strings.Contains(s, "=>") || strings.Contains(s, "sourceMappingURL") || strings.Contains(s, "webpack")
}

func looksLikeHTML(body []byte) bool {
	s := strings.ToLower(string(firstN(body, 2048)))
	return strings.Contains(s, "<html") || strings.Contains(s, "<!doctype html") || strings.Contains(s, "<title")
}

func firstHeaderToken(v string) string {
	if idx := strings.Index(v, ";"); idx >= 0 {
		v = v[:idx]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

func shouldSkipCrawlerCandidate(cfg *Config, u *url.URL) bool {
	if shouldSkipCrawlURL(u) {
		return true
	}
	if cfg != nil && cfg.IsCrawlBlocked(u) {
		verbosef(cfg, "robots blocked crawl path: %s", u.String())
		return true
	}
	return false
}
