# Nikatra

Nikatra is a defensive web vulnerability and misconfiguration scanner for authorized blue-team assessments.

Version: v1.0.0

## Features

- Safe HTTP scanning with GET, HEAD, and OPTIONS only
- Required `--authorized` confirmation before normal scans
- Security header checks
- TLS certificate and HTTPS redirect checks
- HTTP method exposure checks
- Sensitive path and public metadata discovery
- Same-origin crawler with rate limiting
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
./nikatra --target https://example.com --authorized --respect-robots --verbose
./nikatra --target https://example.com --authorized --templates examples/templates/basic.json
./nikatra --config examples/nikatra.config.json
```

## Legal use

Run Nikatra only against systems you own or are explicitly authorized to test. Nikatra is designed for defensive review and hardening. It does not exploit, brute force, bypass, evade, or perform destructive requests.

## Repository

Recommended repository path:

```text
github.com/CodeWithAmeer/Nikatra
```

## License

MIT License.
