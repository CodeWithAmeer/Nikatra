package main

import (
	"regexp"
	"strings"
)

type sitemapURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func confirmRobotsSitemap(resp *ResponseData, soft *Soft404Profile) (bool, int, string) {
	if !responseUsable(resp, soft) || looksLikeHTML(resp.Body) && !strings.Contains(strings.ToLower(resp.URL), "sitemap") {
		return false, 0, ""
	}
	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(resp.URL, "robots.txt") && (strings.Contains(lower, "user-agent:") || strings.Contains(lower, "disallow:")) {
		return true, 95, "robots.txt directives detected."
	}
	if strings.Contains(resp.URL, "sitemap.xml") && (strings.Contains(lower, "<urlset") || strings.Contains(lower, "<sitemapindex")) {
		return true, 95, "sitemap XML markers detected."
	}
	return false, 0, ""
}

func ParseRobotsPolicy(text string) *RobotsPolicy {
	policy := &RobotsPolicy{}
	applies := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "user-agent":
			applies = val == "*"
		case "disallow":
			if applies && val != "" {
				policy.Disallow = append(policy.Disallow, val)
			}
		case "allow":
			if applies && val != "" {
				policy.Allow = append(policy.Allow, val)
			}
		}
	}
	return policy
}

func robotsMatch(rule, path string) bool {
	if rule == "" {
		return false
	}
	if rule == "/" {
		return true
	}
	if strings.Contains(rule, "*") || strings.Contains(rule, "$") {
		quoted := regexp.QuoteMeta(rule)
		quoted = strings.ReplaceAll(quoted, "\\*", ".*")
		quoted = strings.TrimSuffix(quoted, "\\$") + "$"
		re, err := regexp.Compile("^" + quoted)
		return err == nil && re.MatchString(path)
	}
	return strings.HasPrefix(path, rule)
}
