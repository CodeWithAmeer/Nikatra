package main

import (
	"net/http"
)

func CorePathChecks() []PathCheck {
	return []PathCheck{
		{ID: "git-dir", Name: "Public .git directory indicator", Category: "Information Disclosure", Severity: SeverityHigh, Description: "The site appears to expose Git repository metadata.", Recommendation: "Remove .git from the web root and block dot-directories at the web server.", Paths: []string{"/.git/"}, Method: http.MethodGet, Confidence: 85, Tags: []string{"git", "exposure"}, Confirm: confirmGitDirectory},
		{ID: "git-config", Name: "Public .git/config exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A Git config file appears publicly readable.", Recommendation: "Remove .git from the web root and rotate credentials that may have been committed.", Paths: []string{"/.git/config"}, Method: http.MethodGet, Confidence: 95, Tags: []string{"git", "config", "exposure"}, Confirm: confirmGitConfig},
		{ID: "env-file", Name: ".env file exposed", Category: "Information Disclosure", Severity: SeverityCritical, Description: "An environment file appears publicly readable and may contain secrets.", Recommendation: "Remove .env files from the web root, block dotfiles, and rotate any exposed secrets.", Paths: []string{"/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup"}, Method: http.MethodGet, Confidence: 95, Tags: []string{"env", "secrets"}, Confirm: confirmEnvFile},
		{ID: "backup-archive", Name: "Backup/archive file exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A backup or archive file appears publicly accessible with matching file signatures.", Recommendation: "Remove backup archives from the web root and store backups outside public paths.", Paths: []string{"/backup.zip", "/backup.tar.gz", "/backup.gz", "/site.zip", "/www.zip"}, Method: http.MethodGet, Confidence: 90, Tags: []string{"backup", "archive"}, Confirm: confirmArchive},
		{ID: "sql-dump", Name: "SQL dump file exposed", Category: "Information Disclosure", Severity: SeverityCritical, Description: "A database dump appears publicly accessible.", Recommendation: "Remove database dumps from web-accessible paths and rotate credentials if secrets were exposed.", Paths: []string{"/backup.sql", "/db.sql", "/database.sql", "/dump.sql"}, Method: http.MethodGet, Confidence: 95, Tags: []string{"database", "dump"}, Confirm: confirmSQLDump},
		{ID: "ds-store", Name: ".DS_Store file exposed", Category: "Information Disclosure", Severity: SeverityMedium, Description: "A macOS .DS_Store file appears publicly accessible.", Recommendation: "Remove .DS_Store files from production and block hidden files at the web server.", Paths: []string{"/.DS_Store"}, Method: http.MethodGet, Confidence: 90, Tags: []string{"metadata"}, Confirm: confirmDSStore},
		{ID: "phpinfo", Name: "phpinfo page exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A phpinfo page appears publicly accessible.", Recommendation: "Remove phpinfo pages from production and rotate any secrets visible in output.", Paths: []string{"/phpinfo.php", "/info.php"}, Method: http.MethodGet, Confidence: 95, Tags: []string{"php", "debug"}, Confirm: confirmPHPInfo},
		{ID: "apache-status", Name: "Apache server-status/server-info exposed", Category: "Information Disclosure", Severity: SeverityMedium, Description: "Apache status or info output appears publicly accessible.", Recommendation: "Restrict server-status/server-info to trusted administrators or disable the handlers.", Paths: []string{"/server-status", "/server-info"}, Method: http.MethodGet, Confidence: 85, Tags: []string{"apache", "status"}, Confirm: confirmApacheStatus},
		{ID: "admin-panel", Name: "Public administration or login panel detected", Category: "Exposure", Severity: SeverityLow, Description: "A public administrative or login panel was detected. This can be intended, but should be reviewed.", Recommendation: "Restrict administrative interfaces by network, SSO, MFA, and monitoring where appropriate.", Paths: []string{"/admin/", "/login/", "/administrator/", "/wp-admin/", "/wp-login.php", "/user/login"}, Method: http.MethodGet, Confidence: 65, Tags: []string{"admin", "login"}, Confirm: confirmAdminPanel},
		{ID: "wordpress-surface", Name: "WordPress public surface detected", Category: "CMS", Severity: SeverityInfo, Description: "WordPress-related endpoints are visible.", Recommendation: "Keep WordPress core, plugins, and themes updated; restrict administrative access and disable unused endpoints.", Paths: []string{"/wp-content/", "/wp-json/", "/xmlrpc.php", "/readme.html"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"wordpress", "cms"}, Confirm: confirmWordPressSurface},
		{ID: "joomla-surface", Name: "Joomla public surface detected", Category: "CMS", Severity: SeverityInfo, Description: "Joomla-related endpoints are visible.", Recommendation: "Keep Joomla and extensions updated; restrict administrative access.", Paths: []string{"/administrator/", "/language/en-GB/en-GB.xml"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"joomla", "cms"}, Confirm: confirmJoomlaSurface},
		{ID: "drupal-surface", Name: "Drupal public surface detected", Category: "CMS", Severity: SeverityInfo, Description: "Drupal-related endpoints are visible.", Recommendation: "Keep Drupal and modules updated; remove public changelog files if not needed.", Paths: []string{"/CHANGELOG.txt", "/core/CHANGELOG.txt", "/user/login"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"drupal", "cms"}, Confirm: confirmDrupalSurface},
		{ID: "robots-sitemap", Name: "Robots or sitemap file exposed", Category: "Discovery", Severity: SeverityInfo, Description: "robots.txt or sitemap.xml is publicly accessible and may disclose paths.", Recommendation: "Review robots.txt and sitemap.xml to ensure they do not reveal sensitive internal paths.", Paths: []string{"/robots.txt", "/sitemap.xml"}, Method: http.MethodGet, Confidence: 60, Tags: []string{"discovery"}, Confirm: confirmRobotsSitemap},
		{ID: "security-txt", Name: "security.txt published", Category: "Discovery", Severity: SeverityInfo, Description: "A security.txt policy file is published.", Recommendation: "Keep security.txt current with monitored contact details.", Paths: []string{"/.well-known/security.txt"}, Method: http.MethodGet, Confidence: 70, Tags: []string{"securitytxt"}, Confirm: confirmSecurityTxt},
		{ID: "debug-endpoint", Name: "Debug endpoint exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A debug endpoint appears publicly accessible.", Recommendation: "Disable debug endpoints in production or restrict them to trusted administrators.", Paths: []string{"/debug", "/debug/vars"}, Method: http.MethodGet, Confidence: 85, Tags: []string{"debug"}, Confirm: confirmDebugEndpoint},
		{ID: "spring-actuator", Name: "Spring actuator endpoint exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A Spring Boot actuator endpoint appears publicly accessible.", Recommendation: "Restrict actuator endpoints and expose only health information intended for public access.", Paths: []string{"/actuator", "/actuator/env", "/actuator/health", "/actuator/prometheus"}, Method: http.MethodGet, Confidence: 90, Tags: []string{"spring", "actuator"}, Confirm: confirmActuator},
		{ID: "api-docs", Name: "API documentation exposed", Category: "Information Disclosure", Severity: SeverityLow, Description: "API documentation appears publicly accessible.", Recommendation: "Restrict internal API docs or ensure public docs expose only intended endpoints.", Paths: []string{"/api/docs", "/swagger", "/swagger/", "/swagger-ui/", "/swagger.json", "/openapi.json"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"api", "docs"}, Confirm: confirmAPIDocs},
		{ID: "java-web-inf", Name: "Java WEB-INF file exposed", Category: "Information Disclosure", Severity: SeverityHigh, Description: "A Java WEB-INF descriptor appears publicly readable.", Recommendation: "Block WEB-INF from public access at the web server or application server.", Paths: []string{"/WEB-INF/web.xml"}, Method: http.MethodGet, Confidence: 90, Tags: []string{"java"}, Confirm: confirmWebXML},
		{ID: "config-backup", Name: "Configuration backup file exposed", Category: "Information Disclosure", Severity: SeverityCritical, Description: "A configuration backup file appears publicly readable.", Recommendation: "Remove backup config files from web-accessible paths and rotate exposed credentials.", Paths: []string{"/config.php.bak", "/wp-config.php.bak"}, Method: http.MethodGet, Confidence: 95, Tags: []string{"config", "backup"}, Confirm: confirmConfigBackup},
		{ID: "package-manifest", Name: "Package manifest exposed", Category: "Information Disclosure", Severity: SeverityLow, Description: "A package or dependency manifest appears publicly readable.", Recommendation: "Remove manifests from public paths unless intentionally published.", Paths: []string{"/composer.json", "/composer.lock", "/package.json", "/yarn.lock", "/package-lock.json", "/pnpm-lock.yaml", "/go.mod", "/go.sum", "/pom.xml"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"manifest"}, Confirm: confirmPackageManifest},
		{ID: "crossdomain-policy", Name: "Legacy cross-domain policy exposed", Category: "Security Policy", Severity: SeverityLow, Description: "A Flash/Silverlight cross-domain policy file is publicly accessible.", Recommendation: "Remove legacy policy files or restrict them to trusted domains only.", Paths: []string{"/crossdomain.xml", "/clientaccesspolicy.xml"}, Method: http.MethodGet, Confidence: 75, Tags: []string{"policy"}, Confirm: confirmCrossDomainPolicy},
	}

}

func BuildPathChecks() []PathCheck {
	return BuildPathChecksForProfile("full")
}

func BuildPathChecksForProfile(profile string) []PathCheck {
	normalized, err := normalizeScanProfile(profile)
	if err != nil {
		normalized = "basic"
	}
	checks := CorePathChecks()
	switch normalized {
	case "basic":
		return checks
	case "standard":
		return append(checks, filterPathChecksByMinimumSeverity(ExpandedPathChecks(), SeverityHigh)...)
	case "full", "paranoid":
		checks = append(checks, ExpandedPathChecks()...)
		checks = append(checks, ExtendedPathChecksForLargeAuditCoverage()...)
		return checks
	default:
		return checks
	}
}
