package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func LoadTemplateChecks(path string) ([]PathCheck, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(p), ".json") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = append(files, path)
	}
	sort.Strings(files)
	var checks []PathCheck
	for _, f := range files {
		loaded, err := loadTemplateFile(f)
		if err != nil {
			return checks, err
		}
		checks = append(checks, loaded...)
	}
	return checks, nil
}

func loadTemplateFile(path string) ([]PathCheck, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 5*1024*1024 {
		return nil, fmt.Errorf("template file too large: %s", path)
	}
	var templates []ExternalTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("template parse %s: %w", path, err)
	}
	checks := make([]PathCheck, 0, len(templates))
	for _, t := range templates {
		c, err := templateToPathCheck(t)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", t.ID, err)
		}
		checks = append(checks, c)
	}
	return checks, nil
}

func templateToPathCheck(t ExternalTemplate) (PathCheck, error) {
	id := strings.ToLower(strings.TrimSpace(t.ID))
	if id == "" {
		return PathCheck{}, errors.New("id is required")
	}
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !isAllowedRequestMethod(method) {
		return PathCheck{}, fmt.Errorf("unsafe method rejected: %s", method)
	}
	sev, err := parseSeverity(t.Severity)
	if err != nil {
		return PathCheck{}, err
	}
	if len(t.Paths) == 0 {
		return PathCheck{}, errors.New("paths are required")
	}
	for i, p := range t.Paths {
		if !strings.HasPrefix(p, "/") {
			return PathCheck{}, fmt.Errorf("path must start with /: %s", p)
		}
		t.Paths[i] = cleanURLPath(p)
	}
	for _, pat := range append(append([]string{}, t.BodyRegex...), t.NegativeBodyRegex...) {
		if _, err := regexp.Compile(pat); err != nil {
			return PathCheck{}, fmt.Errorf("invalid body regex %q: %w", pat, err)
		}
	}
	for _, pat := range t.EvidenceRegex {
		if _, err := regexp.Compile(pat); err != nil {
			return PathCheck{}, fmt.Errorf("invalid evidence regex %q: %w", pat, err)
		}
	}
	for h, pat := range t.HeaderRegex {
		if strings.TrimSpace(h) == "" {
			return PathCheck{}, errors.New("header regex name is empty")
		}
		if _, err := regexp.Compile(pat); err != nil {
			return PathCheck{}, fmt.Errorf("invalid header regex %q: %w", pat, err)
		}
	}
	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = id
	}
	cat := strings.TrimSpace(t.Category)
	if cat == "" {
		cat = "Template"
	}
	desc := strings.TrimSpace(t.Description)
	if desc == "" {
		desc = "External safe observational template matched."
	}
	rec := strings.TrimSpace(t.Recommendation)
	if rec == "" {
		rec = "Review the exposed resource and restrict it if it is not intentionally public."
	}
	confidence := clampInt(t.Confidence, 1, 100)
	if t.Confidence == 0 {
		confidence = 70
	}
	return PathCheck{ID: id, Name: name, Category: cat, Severity: sev, Description: desc, Recommendation: rec, Paths: t.Paths, Method: method, StatusCodes: t.StatusCodes, BodyRegex: t.BodyRegex, HeaderRegex: t.HeaderRegex, NegativeBodyRegex: t.NegativeBodyRegex, EvidenceRegex: t.EvidenceRegex, Confidence: confidence, Tags: t.Tags}, nil
}

func confirmPathCheck(check PathCheck, resp *ResponseData, soft404 *Soft404Profile) (bool, int, string) {
	if check.Confirm != nil && len(check.BodyRegex) == 0 && len(check.HeaderRegex) == 0 && len(check.NegativeBodyRegex) == 0 && len(check.StatusCodes) == 0 {
		return check.Confirm(resp, soft404)
	}
	if check.Confirm != nil {
		if ok, confidence, evidence := check.Confirm(resp, soft404); ok {
			return ok, confidence, evidence
		}
	}
	return confirmTemplateLike(check, resp, soft404)
}

func confirmTemplateLike(check PathCheck, resp *ResponseData, soft404 *Soft404Profile) (bool, int, string) {
	if resp == nil {
		return false, 0, ""
	}
	if ok, _, _ := soft404.Decision(resp); ok {
		return false, 0, ""
	}
	if len(check.StatusCodes) > 0 && !intInSlice(resp.StatusCode, check.StatusCodes) {
		return false, 0, ""
	}
	body := safeTextPreview(resp.Body)
	for _, pat := range check.NegativeBodyRegex {
		if regexp.MustCompile(pat).MatchString(body) {
			return false, 0, ""
		}
	}
	var evidence []string
	matched := 0
	for _, pat := range check.BodyRegex {
		re := regexp.MustCompile(pat)
		m := re.FindString(body)
		if m == "" {
			return false, 0, ""
		}
		matched++
		evidence = append(evidence, "body_regex="+truncateString(m, 160))
	}
	for h, pat := range check.HeaderRegex {
		v := resp.Headers.Get(h)
		if v == "" {
			return false, 0, ""
		}
		re := regexp.MustCompile(pat)
		m := re.FindString(v)
		if m == "" {
			return false, 0, ""
		}
		matched++
		evidence = append(evidence, "header "+h+"="+truncateString(m, 160))
	}
	for _, pat := range check.EvidenceRegex {
		re := regexp.MustCompile(pat)
		if m := re.FindString(body); m != "" {
			evidence = append(evidence, "evidence="+truncateString(m, 160))
		}
	}
	if len(check.BodyRegex) == 0 && len(check.HeaderRegex) == 0 && len(check.StatusCodes) == 0 {
		return false, 0, ""
	}
	if len(check.BodyRegex) == 0 && len(check.HeaderRegex) == 0 && resp.StatusCode == 200 && looksLikeHTML(resp.Body) {
		return false, 0, ""
	}
	confidence := check.Confidence
	if confidence == 0 {
		confidence = 60
	}
	if matched > 0 {
		confidence = minInt(100, confidence+10)
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "template matched configured status/headers/body conditions")
	}
	return true, confidence, strings.Join(evidence, "; ")
}
