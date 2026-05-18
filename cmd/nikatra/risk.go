package main

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
)

func NewFinding(checkID, name, category string, severity Severity, confidence int, u, method string, status int, evidence, description, recommendation string) Finding {
	confidence = clampInt(confidence, 1, 100)
	evidence = sanitizeEvidence(evidence)
	f := Finding{
		CheckID:        strings.ToLower(checkID),
		Name:           name,
		Category:       category,
		Severity:       severity,
		Confidence:     confidence,
		URL:            u,
		Method:         method,
		StatusCode:     status,
		Evidence:       truncateString(evidence, 600),
		Description:    description,
		Recommendation: recommendation,
	}
	f.ID = f.CheckID + "-" + findingHash(f.URL+"|"+f.Evidence)
	if f.Evidence != "" {
		f.EvidenceItems = []Evidence{{Type: "summary", Value: f.Evidence}}
	}
	return f
}

func DedupeFindings(findings []Finding) []Finding {
	best := map[string]Finding{}
	for _, f := range findings {
		if f.CheckID == "" {
			f.CheckID = strings.ToLower(slug(f.Name))
		}
		keyURL := f.URL
		if u, err := url.Parse(f.URL); err == nil {
			path := cleanURLPath(u.Path)
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			keyURL = normalizeHost(u.Host) + path
		}
		key := ""
		if f.Severity == SeverityInfo && strings.EqualFold(f.Category, "Discovery") {
			key = "discovery|" + strings.ToLower(keyURL)
		} else {
			evidenceHash := findingHash(strings.ToLower(strings.TrimSpace(f.Evidence)))
			key = f.CheckID + "|" + strings.ToLower(keyURL) + "|" + evidenceHash
		}
		prev, ok := best[key]
		if !ok || findingDedupePriority(f) > findingDedupePriority(prev) || severityRank[f.Severity] > severityRank[prev.Severity] || f.Confidence > prev.Confidence {
			best[key] = f
		}
	}
	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	return out
}

func findingDedupePriority(f Finding) int {
	p := severityRank[f.Severity]*1000 + clampInt(f.Confidence, 0, 100)
	id := strings.ToLower(f.CheckID)
	name := strings.ToLower(f.Name)
	if id == "security-txt" || id == "robots-sitemap" {
		p += 500
	}
	if strings.Contains(name, "public discovery or policy") || strings.Contains(name, "public discovery, metadata") {
		p -= 250
	}
	return p
}

func SortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if severityRank[findings[i].Severity] != severityRank[findings[j].Severity] {
			return severityRank[findings[i].Severity] > severityRank[findings[j].Severity]
		}
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Name < findings[j].Name
	})
}

func CalculateRisk(findings []Finding) RiskSummary {
	if len(findings) == 0 {
		return RiskSummary{Score: 0, Level: SeverityInfo, TopReasons: []string{"No findings were identified by the configured checks."}}
	}
	byCheck := map[string]float64{}
	categoryCounts := map[string]int{}
	strongCritical := false
	strongHigh := false
	infoOnly := true
	for _, f := range findings {
		conf := clampInt(f.Confidence, 1, 100)
		if f.Severity != SeverityInfo {
			infoOnly = false
		}
		confirmedBonus := 1.0
		lowEvidence := strings.TrimSpace(f.Evidence) == "" || strings.Contains(strings.ToLower(f.Evidence), "header") && f.Category == "Security Headers"
		if lowEvidence {
			confirmedBonus = 0.82
		}
		categoryCounts[f.Category]++
		catN := categoryCounts[f.Category]
		categoryDiminish := 1.0
		if catN > 1 {
			categoryDiminish = 1.0 / math.Sqrt(float64(catN))
		}
		w := severityWeight[f.Severity] * (float64(conf) / 100.0) * confirmedBonus * categoryDiminish
		if f.Severity == SeverityInfo {
			w = math.Min(w, 0.8)
		}
		if w > byCheck[f.CheckID] {
			byCheck[f.CheckID] = w
		}
		if f.Severity == SeverityCritical && conf >= 80 && strings.TrimSpace(f.Evidence) != "" {
			strongCritical = true
		}
		if f.Severity == SeverityHigh && conf >= 80 && strings.TrimSpace(f.Evidence) != "" {
			strongHigh = true
		}
	}
	scoreFloat := 0.0
	for _, w := range byCheck {
		scoreFloat += w
	}
	if len(categoryCounts) > 1 && !infoOnly {
		scoreFloat += math.Min(8, float64(len(categoryCounts)-1)*1.5)
	}
	if infoOnly {
		scoreFloat = math.Min(scoreFloat, 8)
	}
	score := int(math.Round(math.Min(100, scoreFloat)))
	if strongCritical && score < 90 {
		score = 90
	}
	if !strongCritical && score > 89 {
		score = 89
	}
	if !strongCritical && !strongHigh && score > 69 {
		score = 69
	}
	level := SeverityInfo
	switch {
	case strongCritical && score >= 90:
		level = SeverityCritical
	case score >= 70:
		level = SeverityHigh
	case score >= 40:
		level = SeverityMedium
	case score >= 12:
		level = SeverityLow
	default:
		level = SeverityInfo
	}
	if level == SeverityCritical && !strongCritical {
		level = SeverityHigh
	}
	reasons := topRiskReasons(findings, 5)
	return RiskSummary{Score: score, Level: level, TopReasons: reasons}
}

func topRiskReasons(findings []Finding, limit int) []string {
	copyFindings := append([]Finding(nil), findings...)
	SortFindings(copyFindings)
	seen := map[string]bool{}
	var out []string
	for _, f := range copyFindings {
		key := f.CheckID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fmt.Sprintf("%s: %s (%s, confidence %d%%)", f.Severity, f.Name, f.Category, f.Confidence))
		if len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, "No risk-driving findings were identified.")
	}
	return out
}

func hasFindingAtOrAbove(findings []Finding, threshold Severity) bool {
	for _, f := range findings {
		if severityRank[f.Severity] >= severityRank[threshold] {
			return true
		}
	}
	return false
}
