# Usage

Build:

```bash
go build -o nikatra ./cmd/nikatra
```

Run self tests:

```bash
./nikatra --self-test
```

Run local test server scan:

```bash
./nikatra --self-test-server --format html --output selftest-report.html
```

Authorized scan:

```bash
./nikatra --target https://example.com --authorized --format html --output report.html
```

Use only on systems you own or have permission to test.


## Safer defaults and scan profiles

Default path scanning uses `--scan-profile basic`. Available profiles are:

- `basic`: curated core checks with modest request volume.
- `standard`: core checks plus broader high-severity configuration exposure checks.
- `full`: all bundled path checks.
- `paranoid`: alias for the largest bundled profile.

Examples:

```bash
./nikatra --target https://example.com --authorized --scan-profile standard --respect-robots
./nikatra --target https://example.com --authorized --scan-profile full --safe-mode=false --rate-limit 2
```

`--safe-mode` is enabled by default and caps high-noise settings such as excessive concurrency, disabled rate limits, and very large crawl page counts. It does not enable unsafe methods when disabled; Nikatra remains limited to safe observational HTTP methods.

With `--respect-robots`, robots.txt rules are honored for crawling, soft-404 calibration paths, discovered assets, and path/template checks.

When `--allow-external` is used, Nikatra still strips cookies, Authorization, Basic Auth, bearer tokens, and custom headers from external-origin requests to avoid credential leakage.
