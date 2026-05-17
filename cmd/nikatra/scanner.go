package main

import (
	"sort"
)

func BuildReportConfig(cfg *Config) ReportConfig {
	names := make([]string, 0, len(cfg.CustomHeaders))
	for _, kv := range cfg.CustomHeaders {
		names = append(names, kv.Name)
	}
	sort.Strings(names)
	failOn := ""
	if cfg.FailOnSet {
		failOn = string(cfg.FailOn)
	}
	return ReportConfig{
		TargetInput:         cfg.TargetInput,
		Concurrency:         cfg.Concurrency,
		Timeout:             cfg.Timeout.String(),
		UserAgent:           cfg.UserAgent,
		OutputFormat:        cfg.OutputFormat,
		SafeMode:            cfg.SafeMode,
		MaxRedirects:        cfg.MaxRedirects,
		RateLimit:           cfg.RateLimit,
		ScanDepth:           cfg.ScanDepth,
		MaxPages:            cfg.MaxPages,
		AllowExternal:       cfg.AllowExternal,
		FollowSitemap:       cfg.FollowSitemap,
		FollowRobots:        cfg.FollowRobots,
		RespectRobots:       cfg.RespectRobots,
		TemplatesPath:       cfg.TemplatesPath,
		TemplateCount:       cfg.TemplateCount,
		ConfigPath:          cfg.ConfigPath,
		Verbose:             cfg.Verbose,
		IncludeChecks:       cfg.IncludeList,
		ExcludeChecks:       cfg.ExcludeList,
		ResponseLimitBytes:  cfg.ResponseLimitBytes,
		Retries:             cfg.Retries,
		CustomHeaderNames:   names,
		CookiesSupplied:     cfg.Cookie != "",
		BearerTokenSupplied: cfg.BearerToken != "",
		BasicAuthSupplied:   cfg.BasicAuth != "",
		BaselinePath:        cfg.BaselinePath,
		FailOn:              failOn,
	}
}
