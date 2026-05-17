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
