package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func LoadConfigFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var jc NikatraJSONConfig
	if err := json.Unmarshal(data, &jc); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}
	if jc.Target != "" {
		cfg.TargetInput = jc.Target
	}
	if jc.Concurrency != nil {
		cfg.Concurrency = *jc.Concurrency
	}
	if jc.Timeout != "" {
		if err := (&durationFlag{value: cfg.Timeout}).Set(jc.Timeout); err != nil {
			return err
		}
		d := durationFlag{}
		_ = d.Set(jc.Timeout)
		cfg.Timeout = d.value
	}
	if jc.UserAgent != "" {
		cfg.UserAgent = jc.UserAgent
	}
	if jc.OutputFormat != "" {
		cfg.OutputFormat = jc.OutputFormat
	}
	if jc.Output != "" {
		cfg.OutputPath = jc.Output
	}
	if jc.RateLimit != nil {
		cfg.RateLimit = *jc.RateLimit
	}
	if jc.MaxRedirects != nil {
		cfg.MaxRedirects = *jc.MaxRedirects
	}
	if jc.Depth != nil {
		cfg.ScanDepth = *jc.Depth
	}
	if jc.MaxPages != nil {
		cfg.MaxPages = *jc.MaxPages
	}
	if jc.ResponseLimit != nil {
		cfg.ResponseLimitBytes = *jc.ResponseLimit
	}
	if jc.Retries != nil {
		cfg.Retries = *jc.Retries
	}
	if jc.Authorized != nil {
		cfg.Authorized = *jc.Authorized
	}
	if jc.AllowExternal != nil {
		cfg.AllowExternal = *jc.AllowExternal
	}
	if jc.FollowSitemap != nil {
		cfg.FollowSitemap = *jc.FollowSitemap
	}
	if jc.FollowRobots != nil {
		cfg.FollowRobots = *jc.FollowRobots
	}
	if jc.RespectRobots != nil {
		cfg.RespectRobots = *jc.RespectRobots
	}
	if jc.Verbose != nil {
		cfg.Verbose = *jc.Verbose
	}
	if jc.Cookie != "" {
		cfg.Cookie = jc.Cookie
	}
	if jc.BearerToken != "" {
		cfg.BearerToken = jc.BearerToken
	}
	if jc.BasicAuth != "" {
		cfg.BasicAuth = jc.BasicAuth
	}
	if jc.Templates != "" {
		cfg.TemplatesPath = jc.Templates
	}
	if jc.Baseline != "" {
		cfg.BaselinePath = jc.Baseline
	}
	if jc.FailOn != "" {
		sev, err := parseSeverity(jc.FailOn)
		if err != nil {
			return err
		}
		cfg.FailOn = sev
		cfg.FailOnSet = true
	}
	if len(jc.Include) > 0 {
		cfg.IncludeList, cfg.IncludeChecks = parseCheckList(strings.Join(jc.Include, ","))
	}
	if len(jc.Exclude) > 0 {
		cfg.ExcludeList, cfg.ExcludeChecks = parseCheckList(strings.Join(jc.Exclude, ","))
	}
	if len(jc.Headers) > 0 && string(jc.Headers) != "null" {
		headers, err := parseConfigHeaders(jc.Headers)
		if err != nil {
			return err
		}
		cfg.CustomHeaders = append(cfg.CustomHeaders, headers...)
	}
	return nil
}

func findFlagValue(args []string, name string) string {
	prefix := "--" + name + "="
	for i, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
		if arg == "--"+name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
