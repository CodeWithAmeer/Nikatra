package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
)

func ApplyBaseline(path string, findings []Finding) BaselineComparison {
	if strings.TrimSpace(path) == "" {
		return BaselineComparison{}
	}
	comparison := BaselineComparison{Enabled: true}
	data, err := os.ReadFile(path)
	if err != nil {
		comparison.Error = err.Error()
		for i := range findings {
			findings[i].BaselineStatus = "new"
		}
		comparison.New = len(findings)
		return comparison
	}
	var previous Report
	if err := json.Unmarshal(data, &previous); err != nil {
		comparison.Error = err.Error()
		for i := range findings {
			findings[i].BaselineStatus = "new"
		}
		comparison.New = len(findings)
		return comparison
	}
	prev := map[string]Finding{}
	for _, f := range previous.Findings {
		prev[baselineKey(f)] = f
	}
	curr := map[string]bool{}
	for i := range findings {
		key := baselineKey(findings[i])
		curr[key] = true
		if _, ok := prev[key]; ok {
			findings[i].BaselineStatus = "existing"
			comparison.Existing++
		} else {
			findings[i].BaselineStatus = "new"
			comparison.New++
		}
	}
	for key, old := range prev {
		if !curr[key] {
			old.BaselineStatus = "resolved"
			comparison.Resolved++
			comparison.ResolvedFindings = append(comparison.ResolvedFindings, old)
		}
	}
	SortFindings(comparison.ResolvedFindings)
	return comparison
}

func RenderReport(report *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "html":
		return RenderHTML(report), nil
	case "markdown", "md":
		return RenderMarkdown(report), nil
	case "sarif":
		return RenderSARIF(report)
	case "text", "":
		return RenderText(report), nil
	default:
		return "", fmt.Errorf("unsupported output format %q", format)
	}
}

func RenderText(report *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", report.Tool, report.Version)
	fmt.Fprintf(&b, "Target: %s\n", report.Target)
	fmt.Fprintf(&b, "Timestamp: %s\n", report.Timestamp)
	fmt.Fprintf(&b, "Risk: %s %d/100\n", report.Risk.Level, report.Risk.Score)
	fmt.Fprintf(&b, "Requests: %d, Errors: %d, Bytes read: %d\n", report.HTTPStats.Requests, report.HTTPStats.Errors, report.HTTPStats.BytesRead)
	if len(report.Technologies) > 0 {
		b.WriteString("\nTechnologies:\n")
		for _, t := range report.Technologies {
			v := ""
			if t.Version != "" {
				v = " " + t.Version
			}
			fmt.Fprintf(&b, "- %s%s (confidence %d%%): %s\n", t.Name, v, t.Confidence, t.Evidence)
		}
	}
	b.WriteString("\nTop reasons:\n")
	for _, reason := range report.Risk.TopReasons {
		fmt.Fprintf(&b, "- %s\n", reason)
	}
	b.WriteString("\nFindings:\n")
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		for _, f := range report.Findings {
			status := ""
			if f.BaselineStatus != "" {
				status = " [" + f.BaselineStatus + "]"
			}
			fmt.Fprintf(&b, "\n[%s] %s%s (%s, confidence %d%%)\n", f.Severity, f.Name, status, f.Category, f.Confidence)
			fmt.Fprintf(&b, "  URL: %s\n", f.URL)
			fmt.Fprintf(&b, "  Evidence: %s\n", f.Evidence)
			fmt.Fprintf(&b, "  Recommendation: %s\n", f.Recommendation)
		}
	}
	if report.Baseline.Enabled {
		fmt.Fprintf(&b, "\nBaseline: new=%d existing=%d resolved=%d", report.Baseline.New, report.Baseline.Existing, report.Baseline.Resolved)
		if report.Baseline.Error != "" {
			fmt.Fprintf(&b, " error=%s", report.Baseline.Error)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func RenderMarkdown(report *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s Report\n\n", report.Tool, report.Version)
	fmt.Fprintf(&b, "- **Target:** `%s`\n", report.Target)
	fmt.Fprintf(&b, "- **Timestamp:** `%s`\n", report.Timestamp)
	fmt.Fprintf(&b, "- **Risk:** **%s** `%d/100`\n", report.Risk.Level, report.Risk.Score)
	fmt.Fprintf(&b, "- **Requests:** `%d`  **Errors:** `%d`\n\n", report.HTTPStats.Requests, report.HTTPStats.Errors)
	b.WriteString("## Top reasons\n\n")
	for _, reason := range report.Risk.TopReasons {
		fmt.Fprintf(&b, "- %s\n", escapeMD(reason))
	}
	b.WriteString("\n## Technologies\n\n")
	if len(report.Technologies) == 0 {
		b.WriteString("None detected.\n\n")
	} else {
		b.WriteString("| Name | Version | Confidence | Evidence |\n|---|---:|---:|---|\n")
		for _, t := range report.Technologies {
			fmt.Fprintf(&b, "| %s | %s | %d%% | %s |\n", escapeMD(t.Name), escapeMD(t.Version), t.Confidence, escapeMD(t.Evidence))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Findings\n\n")
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		b.WriteString("| Severity | Confidence | Name | URL | Evidence | Recommendation | Baseline |\n|---|---:|---|---|---|---|---|\n")
		for _, f := range report.Findings {
			fmt.Fprintf(&b, "| %s | %d%% | %s | `%s` | %s | %s | %s |\n", f.Severity, f.Confidence, escapeMD(f.Name), escapeMD(f.URL), escapeMD(f.Evidence), escapeMD(f.Recommendation), escapeMD(f.BaselineStatus))
		}
	}
	return b.String()
}

func RenderHTML(report *Report) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Nikatra Report</title><style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:2rem;line-height:1.45}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ddd;padding:.55rem;vertical-align:top}th{background:#f5f5f5}.sev-CRITICAL{color:#8b0000;font-weight:700}.sev-HIGH{color:#b00020;font-weight:700}.sev-MEDIUM{color:#a15c00;font-weight:700}.sev-LOW{color:#155fa0}.sev-INFO{color:#555}code{background:#f6f8fa;padding:.1rem .25rem;border-radius:4px}</style></head><body>")
	fmt.Fprintf(&b, "<h1>%s %s Report</h1>", html.EscapeString(report.Tool), html.EscapeString(report.Version))
	fmt.Fprintf(&b, "<p><strong>Target:</strong> <code>%s</code><br><strong>Timestamp:</strong> %s<br><strong>Risk:</strong> <span class=\"sev-%s\">%s %d/100</span></p>", html.EscapeString(report.Target), html.EscapeString(report.Timestamp), report.Risk.Level, report.Risk.Level, report.Risk.Score)
	b.WriteString("<h2>Top reasons</h2><ul>")
	for _, reason := range report.Risk.TopReasons {
		fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(reason))
	}
	b.WriteString("</ul><h2>Technologies</h2>")
	if len(report.Technologies) == 0 {
		b.WriteString("<p>None detected.</p>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr>")
		for _, t := range report.Technologies {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%d%%</td><td>%s</td></tr>", html.EscapeString(t.Name), html.EscapeString(t.Version), t.Confidence, html.EscapeString(t.Evidence))
		}
		b.WriteString("</table>")
	}
	b.WriteString("<h2>Findings</h2>")
	if len(report.Findings) == 0 {
		b.WriteString("<p>No findings.</p>")
	} else {
		b.WriteString("<table><tr><th>Severity</th><th>Confidence</th><th>Name</th><th>URL</th><th>Evidence</th><th>Recommendation</th><th>Baseline</th></tr>")
		for _, f := range report.Findings {
			fmt.Fprintf(&b, "<tr><td class=\"sev-%s\">%s</td><td>%d%%</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>", f.Severity, f.Severity, f.Confidence, html.EscapeString(f.Name), html.EscapeString(f.URL), html.EscapeString(f.Evidence), html.EscapeString(f.Recommendation), html.EscapeString(f.BaselineStatus))
		}
		b.WriteString("</table>")
	}
	fmt.Fprintf(&b, "<h2>HTTP statistics</h2><p>Requests: %d, Errors: %d, Bytes read: %d</p>", report.HTTPStats.Requests, report.HTTPStats.Errors, report.HTTPStats.BytesRead)
	b.WriteString("</body></html>\n")
	return b.String()
}

func RenderSARIF(report *Report) (string, error) {
	rules := map[string]map[string]interface{}{}
	var results []map[string]interface{}
	for _, f := range report.Findings {
		rules[f.CheckID] = map[string]interface{}{
			"id":               f.CheckID,
			"name":             f.Name,
			"shortDescription": map[string]interface{}{"text": f.Name},
			"fullDescription":  map[string]interface{}{"text": f.Description},
			"help":             map[string]interface{}{"text": f.Recommendation},
			"properties":       map[string]interface{}{"category": f.Category, "severity": f.Severity, "confidence": f.Confidence},
		}
		level := "note"
		switch f.Severity {
		case SeverityCritical, SeverityHigh:
			level = "error"
		case SeverityMedium:
			level = "warning"
		}
		results = append(results, map[string]interface{}{
			"ruleId":     f.CheckID,
			"level":      level,
			"message":    map[string]interface{}{"text": fmt.Sprintf("%s: %s Evidence: %s", f.Severity, f.Name, f.Evidence)},
			"locations":  []map[string]interface{}{{"physicalLocation": map[string]interface{}{"artifactLocation": map[string]interface{}{"uri": f.URL}}}},
			"properties": map[string]interface{}{"confidence": f.Confidence, "recommendation": f.Recommendation, "baselineStatus": f.BaselineStatus},
		})
	}
	ruleList := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return fmt.Sprint(ruleList[i]["id"]) < fmt.Sprint(ruleList[j]["id"]) })
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{{
			"tool":       map[string]interface{}{"driver": map[string]interface{}{"name": report.Tool, "version": report.Version, "informationUri": "https://example.invalid/nikatra", "rules": ruleList}},
			"results":    results,
			"properties": map[string]interface{}{"target": report.Target, "riskScore": report.Risk.Score, "riskLevel": report.Risk.Level},
		}},
	}
	b, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}
