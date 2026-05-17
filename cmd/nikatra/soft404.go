package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/url"
	"regexp"
	"strings"
)

func (p *Soft404Profile) IsSoft404(resp *ResponseData) bool {
	if p == nil || resp == nil {
		return false
	}
	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		return true
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Headers.Get("Location")
		for _, sample := range p.Samples {
			if sample.StatusCode >= 300 && sample.StatusCode < 400 && redirectsSimilar(sample.Location, loc) {
				return true
			}
		}
		return false
	}
	if resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 403 {
		return false
	}
	title := extractTitle(resp.Body)
	length := len(resp.Body)
	contentType := firstHeaderToken(resp.Headers.Get("Content-Type"))
	hash := bodyHash(resp.Body)
	prefix := normalizedBodyPrefix(resp.Body)
	for _, sample := range p.Samples {
		if sample.StatusCode != resp.StatusCode && !(sample.StatusCode == 200 && resp.StatusCode == 200) {
			continue
		}
		if sample.ContentType != "" && contentType != "" && sample.ContentType != contentType {
			continue
		}
		if sample.Hash != "" && sample.Hash == hash {
			return true
		}
		if sample.BodyPrefix != "" && sample.BodyPrefix == prefix && lengthClose(sample.Length, length, 0.35) {
			return true
		}
		if sample.Title != "" && title != "" && strings.EqualFold(sample.Title, title) && lengthClose(sample.Length, length, 0.25) {
			return true
		}
		if sample.Title == "" && title == "" && lengthClose(sample.Length, length, 0.12) && contentType == sample.ContentType {
			return true
		}
	}
	return false
}

func redirectsSimilar(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	au, aerr := url.Parse(a)
	bu, berr := url.Parse(b)
	if aerr == nil && berr == nil {
		return cleanURLPath(au.Path) == cleanURLPath(bu.Path)
	}
	return a == b
}

func lengthClose(a, b int, tolerance float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	maxv := math.Max(float64(a), float64(b))
	if maxv == 0 {
		return true
	}
	return math.Abs(float64(a-b))/maxv <= tolerance
}

func bodyHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	normalized := bytes.ToLower(bytes.TrimSpace(stripVolatileHTML(body)))
	if len(normalized) > 8192 {
		normalized = normalized[:8192]
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:8])
}

func stripVolatileHTML(body []byte) []byte {
	s := string(body)
	replacements := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b[0-9a-f]{8,}\b`),
		regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+`),
		regexp.MustCompile(`\b\d{10,}\b`),
	}
	for _, re := range replacements {
		s = re.ReplaceAllString(s, "#")
	}
	return []byte(s)
}

func normalizedBodyPrefix(body []byte) string {
	b := bytes.TrimSpace(stripVolatileHTML(body))
	if len(b) > 512 {
		b = b[:512]
	}
	return strings.ToLower(string(b))
}
