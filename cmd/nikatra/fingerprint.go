package main

import (
	"bytes"
	"html"
	"regexp"
	"sort"
	"strings"
)

func Fingerprint(root *ResponseData, pages []PageData) []Technology {
	t := map[string]Technology{}
	add := func(name, version, evidence string, confidence int) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		existing, ok := t[key]
		if !ok || confidence > existing.Confidence || (existing.Version == "" && version != "") {
			t[key] = Technology{Name: name, Version: version, Evidence: truncateString(sanitizeEvidence(evidence), 220), Confidence: clampInt(confidence, 1, 100)}
		}
	}
	if root != nil {
		server := root.Headers.Get("Server")
		if server != "" {
			for _, pair := range []struct{ Marker, Name string }{{"nginx", "nginx"}, {"apache", "Apache"}, {"microsoft-iis", "IIS"}, {"iis", "IIS"}, {"cloudflare", "Cloudflare"}} {
				if strings.Contains(strings.ToLower(server), pair.Marker) {
					add(pair.Name, versionFromText(server, pair.Marker), "Server: "+server, 90)
				}
			}
		}
		xpb := root.Headers.Get("X-Powered-By")
		if xpb != "" {
			lower := strings.ToLower(xpb)
			for _, pair := range []struct{ Marker, Name string }{{"php", "PHP"}, {"express", "Express"}, {"asp.net", "ASP.NET"}, {"node", "Node.js"}, {"next.js", "Next.js"}, {"django", "Django"}, {"laravel", "Laravel"}} {
				if strings.Contains(lower, pair.Marker) {
					add(pair.Name, versionFromText(xpb, pair.Marker), "X-Powered-By: "+xpb, 90)
				}
			}
		}
		for _, c := range root.Headers.Values("Set-Cookie") {
			lc := strings.ToLower(c)
			switch {
			case strings.Contains(lc, "laravel_session"):
				add("Laravel", "", "Cookie laravel_session", 85)
			case strings.Contains(lc, "csrftoken"):
				add("Django", "", "Cookie csrftoken", 65)
			case strings.Contains(lc, "connect.sid"):
				add("Express", "", "Cookie connect.sid", 75)
			case strings.Contains(lc, "php"):
				add("PHP", "", "PHP-like session cookie", 70)
			case strings.Contains(lc, "asp.net"):
				add("ASP.NET", "", "ASP.NET cookie", 80)
			}
		}
	}
	combined := bytes.Buffer{}
	if root != nil {
		combined.Write(root.Body)
	}
	for _, p := range pages {
		combined.Write(p.Body)
		if combined.Len() > 2*1024*1024 {
			break
		}
	}
	body := combined.String()
	lower := strings.ToLower(body)
	genRe := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)`)
	if m := genRe.FindStringSubmatch(body); len(m) > 1 {
		gen := html.UnescapeString(m[1])
		for _, name := range []string{"WordPress", "Joomla", "Drupal", "TYPO3", "Wix"} {
			if strings.Contains(strings.ToLower(gen), strings.ToLower(name)) {
				add(name, versionFromText(gen, strings.ToLower(name)), "generator meta: "+gen, 95)
			}
		}
	}
	markers := []struct {
		Marker, Name string
		Conf         int
	}{
		{"wp-content/", "WordPress", 95}, {"wp-includes/", "WordPress", 90}, {"/wp-json/", "WordPress", 85},
		{"content=\"joomla", "Joomla", 90}, {"/media/system/js/", "Joomla", 75},
		{"drupal-settings-json", "Drupal", 95}, {"/sites/default/", "Drupal", 90},
		{"laravel", "Laravel", 65}, {"__django", "Django", 60}, {"csrfmiddlewaretoken", "Django", 75},
		{"express", "Express", 55}, {"asp.net", "ASP.NET", 80}, {"__next_data__", "Next.js", 95}, {"/_next/", "Next.js", 95},
		{"data-reactroot", "React", 85}, {"react-dom", "React", 80}, {"id=\"app\"", "Vue", 55}, {"__nuxt", "Nuxt", 95},
		{"ng-version", "Angular", 95}, {"spring boot", "Spring Boot", 75}, {"ruby on rails", "Rails", 75},
		{"flask", "Flask", 65}, {"fastapi", "FastAPI", 80}, {"vite", "Vite", 80}, {"webpack", "Webpack", 80},
		{"herokuapp.com", "Heroku", 85}, {"cloudflare", "Cloudflare", 90},
	}
	for _, marker := range markers {
		if strings.Contains(lower, strings.ToLower(marker.Marker)) {
			add(marker.Name, versionFromText(body, strings.ToLower(marker.Name)), "HTML marker: "+marker.Marker, marker.Conf)
		}
	}
	out := make([]Technology, 0, len(t))
	for _, tech := range t {
		out = append(out, tech)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].Name < out[j].Name
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

func TechnologyVersionFindings(technologies []Technology, sourceURL string) []Finding {
	var findings []Finding
	for _, tech := range technologies {
		if tech.Version != "" {
			findings = append(findings, NewFinding("visible-version-"+slug(tech.Name), tech.Name+" version is visible", "Fingerprinting", SeverityLow, tech.Confidence, sourceURL, "GET", 0, tech.Name+" version hint: "+tech.Version+"; evidence: "+tech.Evidence, "A technology version appears visible in headers or page content. This can help attackers select targeted checks.", "Hide detailed version banners where practical and keep the component patched."))
		}
		if hint := oldVersionHint(tech.Name, tech.Version); hint != "" {
			findings = append(findings, NewFinding("old-version-hint-"+slug(tech.Name), tech.Name+" version may be outdated", "Fingerprinting", SeverityMedium, minInt(tech.Confidence, 80), sourceURL, "GET", 0, hint+" Evidence: "+tech.Evidence, "A visible version string appears to indicate an old major version. Nikatra does not claim a CVE from this evidence alone.", "Verify the deployed version from server inventory and upgrade if it is no longer supported."))
		}
	}
	return findings
}

func looksLikeVersionLeak(s string) bool {
	return regexp.MustCompile(`\b\d+(?:\.\d+){0,3}\b`).FindString(s) != ""
}

func EnhanceFingerprinting(in []Technology, root *ResponseData, pages []PageData) []Technology {
	m := map[string]Technology{}
	for _, t := range in {
		m[strings.ToLower(t.Name)] = t
	}
	add := func(name, version, evidence string, confidence int) {
		key := strings.ToLower(name)
		if old, ok := m[key]; !ok || confidence > old.Confidence || (old.Version == "" && version != "") {
			m[key] = Technology{Name: name, Version: version, Evidence: truncateString(sanitizeEvidence(evidence), 220), Confidence: clampInt(confidence, 1, 100)}
		}
	}
	if root != nil {
		for _, hv := range []struct {
			Header, Marker, Name string
			Conf                 int
		}{
			{"Server", "cloudflare", "Cloudflare", 95}, {"Server", "akamai", "Akamai", 90}, {"Server", "fastly", "Fastly", 90}, {"Server", "cloudfront", "CloudFront", 90}, {"Server", "nginx", "nginx", 90}, {"Server", "apache", "Apache", 90}, {"Server", "microsoft-iis", "IIS", 95}, {"Server", "envoy", "Envoy", 80},
			{"X-Vercel-Id", "", "Vercel", 95}, {"X-Nf-Request-Id", "", "Netlify", 95}, {"X-Azure-Ref", "", "Azure Front Door", 90}, {"X-Cache", "cloudfront", "CloudFront", 80}, {"Via", "varnish", "Varnish", 75}, {"CF-Ray", "", "Cloudflare", 95},
		} {
			v := root.Headers.Get(hv.Header)
			if v == "" {
				continue
			}
			if hv.Marker == "" || strings.Contains(strings.ToLower(v), hv.Marker) {
				add(hv.Name, versionFromText(v, hv.Marker), hv.Header+": "+v, hv.Conf)
			}
		}
	}
	buf := strings.Builder{}
	if root != nil {
		buf.Write(root.Body)
	}
	for _, p := range pages {
		if buf.Len() > 2*1024*1024 {
			break
		}
		buf.Write(p.Body)
	}
	body := buf.String()
	lower := strings.ToLower(body)
	markers := []struct {
		Marker, Name string
		Conf         int
	}{
		{"/wp-content/plugins/", "WordPress Plugins", 90}, {"/wp-content/themes/", "WordPress Themes", 90}, {"wp-json", "WordPress REST API", 90}, {"joomla!", "Joomla", 90}, {"drupal-settings-json", "Drupal", 95}, {"laravel_session", "Laravel", 85}, {"django csrf", "Django", 75}, {"ruby on rails", "Rails", 80}, {"spring boot", "Spring Boot", 80}, {"apache tomcat", "Tomcat", 90}, {"x-jenkins", "Jenkins", 90}, {"grafana-app", "Grafana", 95}, {"prometheus", "Prometheus", 75}, {"kubernetes-dashboard", "Kubernetes Dashboard", 90}, {"__next_data__", "Next.js", 95}, {"/_next/static/", "Next.js", 95}, {"__nuxt", "Nuxt", 95}, {"data-reactroot", "React", 85}, {"react-dom", "React", 80}, {"vue.runtime", "Vue", 80}, {"ng-version", "Angular", 95}, {"vite/client", "Vite", 85}, {"sveltekit", "SvelteKit", 85}, {"express", "Express", 60}, {"asp.net", "ASP.NET", 85}, {"phpinfo()", "PHP", 95},
	}
	for _, mk := range markers {
		if strings.Contains(lower, mk.Marker) {
			add(mk.Name, versionFromText(body, strings.ToLower(mk.Name)), "marker: "+mk.Marker, mk.Conf)
		}
	}
	out := make([]Technology, 0, len(m))
	for _, t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].Name < out[j].Name
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}
