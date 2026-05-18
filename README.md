# Nikatra

Nikatra is a defensive web vulnerability and misconfiguration scanner for authorized blue-team assessments.

Version: v1.0.0

## Features

- Safe HTTP scanning with GET, HEAD, and OPTIONS only
- Required `--authorized` confirmation before normal scans
- Security header checks
- TLS certificate and HTTPS redirect checks
- HTTP method exposure checks
- Sensitive path and public metadata discovery with selectable scan profiles
- Same-origin crawler with rate limiting and robots.txt-aware skip logic when enabled
- Technology fingerprinting
- JSON template checks
- JSON, HTML, Markdown, text, and SARIF reports
- Baseline comparison support
- Built-in self-test and local self-test server

## Install

```bash
go build -o nikatra ./cmd/nikatra
```

On Windows PowerShell:

```powershell
go build -o nikatra.exe ./cmd/nikatra
```

## Quick safety test

```bash
./nikatra --self-test
./nikatra --self-test-server --format html --output selftest-report.html
```

Windows:

```powershell
.\nikatra.exe --self-test
.\nikatra.exe --self-test-server --format html --output selftest-report.html
```

## Authorized scan

```bash
./nikatra --target https://example.com --authorized --format html --output report.html
```

Windows:

```powershell
.\nikatra.exe --target https://example.com --authorized --format html --output report.html
```

## Useful options

```bash
./nikatra --target https://example.com --authorized --depth 2 --max-pages 100 --rate-limit 3 --timeout 10s
./nikatra --target https://example.com --authorized --scan-profile standard --respect-robots --verbose
./nikatra --target https://example.com --authorized --templates examples/templates/basic.json
./nikatra --config examples/nikatra.config.json
```

## Scan profiles

Nikatra defaults to `--scan-profile basic` to keep the default request volume modest. Use `standard` for broader high-signal path checks, or `full` / `paranoid` for the largest audit surface when you have explicit permission and enough maintenance window.

`--safe-mode` is enabled by default. It keeps requests conservative by capping high-noise settings; use `--safe-mode=false` only when you intentionally want to lift those caps. Disabling safe mode does not enable destructive HTTP methods.

When `--respect-robots` is enabled, Nikatra applies the robots policy to crawling, soft-404 calibration paths, discovered assets, and built-in/template path checks.

Nikatra also strips cookies, Authorization, Basic Auth, bearer tokens, and custom headers from external-origin requests, even when `--allow-external` is enabled.

## Legal use

Run Nikatra only against systems you own or are explicitly authorized to test. Nikatra is designed for defensive review and hardening. It does not exploit, brute force, bypass, evade, or perform destructive requests.

## Repository

Recommended repository path:

```text
github.com/CodeWithAmeer/Nikatra
```

## License

MIT License.
