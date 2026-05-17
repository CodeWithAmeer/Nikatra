package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func CheckTLS(ctx context.Context, cfg *Config, base *url.URL) (TLSSummary, []Finding) {
	summary := TLSSummary{Enabled: base.Scheme == "https", Host: base.Hostname(), TrustedChain: true}
	if base.Scheme != "https" {
		return summary, nil
	}
	port := base.Port()
	if port == "" {
		port = "443"
	}
	summary.Port = port
	address := net.JoinHostPort(base.Hostname(), port)
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	tlsCfg := &tls.Config{ServerName: base.Hostname(), InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsCfg)
	if err != nil {
		summary.Error = err.Error()
		return summary, []Finding{NewFinding("tls-handshake-failed", "TLS handshake failed", "TLS", SeverityHigh, 95, base.String(), "TLS", 0, truncateString(err.Error(), 240), "Nikatra could not complete a TLS handshake with the target.", "Review certificate chain, supported TLS versions, SNI configuration, and listener availability.")}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	summary.Version = tlsVersionName(state.Version)
	summary.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	var findings []Finding
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, NewFinding("legacy-tls-version", "Legacy TLS version negotiated", "TLS", SeverityHigh, 95, base.String(), "TLS", 0, "Negotiated protocol: "+summary.Version, "The server negotiated a legacy TLS protocol version.", "Disable TLS 1.0 and TLS 1.1. Prefer TLS 1.2 or TLS 1.3 with modern cipher suites."))
	}
	if len(state.PeerCertificates) == 0 {
		summary.Error = "server did not present a certificate"
		findings = append(findings, NewFinding("missing-tls-certificate", "TLS certificate missing", "TLS", SeverityHigh, 95, base.String(), "TLS", 0, "No peer certificate was available.", "The server did not present a certificate during the TLS handshake.", "Install a valid certificate chain for the target hostname."))
		return summary, findings
	}
	cert := state.PeerCertificates[0]
	now := time.Now()
	summary.CertificateSubject = cert.Subject.String()
	summary.CertificateIssuer = cert.Issuer.String()
	summary.SANs = append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		summary.SANs = append(summary.SANs, ip.String())
	}
	sort.Strings(summary.SANs)
	summary.NotBefore = cert.NotBefore.Format(time.RFC3339)
	summary.NotAfter = cert.NotAfter.Format(time.RFC3339)
	summary.DaysUntilExpiry = int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
	summary.Expired = now.After(cert.NotAfter)
	summary.NotYetValid = now.Before(cert.NotBefore)
	summary.SelfSigned = cert.CheckSignatureFrom(cert) == nil && cert.Subject.String() == cert.Issuer.String()
	summary.HostnameMismatch = cert.VerifyHostname(base.Hostname()) != nil
	roots, _ := x509.SystemCertPool()
	verifyOpts := x509.VerifyOptions{DNSName: base.Hostname(), Roots: roots, CurrentTime: now, Intermediates: x509.NewCertPool()}
	for _, intermediate := range state.PeerCertificates[1:] {
		verifyOpts.Intermediates.AddCert(intermediate)
	}
	if _, err := cert.Verify(verifyOpts); err != nil {
		summary.TrustedChain = false
		findings = append(findings, NewFinding("tls-untrusted-chain", "TLS certificate chain is not trusted", "TLS", SeverityHigh, 90, base.String(), "TLS", 0, truncateString(err.Error(), 240), "The certificate chain could not be validated against the system trust store.", "Deploy a certificate chain trusted by clients, including required intermediates."))
	}
	if summary.Expired {
		findings = append(findings, NewFinding("tls-certificate-expired", "TLS certificate is expired", "TLS", SeverityHigh, 100, base.String(), "TLS", 0, "Certificate expired at "+summary.NotAfter, "The target certificate is past its NotAfter date.", "Renew and deploy a valid TLS certificate immediately."))
	} else if summary.DaysUntilExpiry <= 30 {
		findings = append(findings, NewFinding("tls-certificate-expiring", "TLS certificate expires soon", "TLS", SeverityMedium, 95, base.String(), "TLS", 0, fmt.Sprintf("Certificate expires in %d days at %s", summary.DaysUntilExpiry, summary.NotAfter), "The target certificate is close to expiry.", "Renew the certificate before expiry and monitor certificate lifecycle automation."))
	}
	if summary.NotYetValid {
		findings = append(findings, NewFinding("tls-certificate-not-yet-valid", "TLS certificate is not yet valid", "TLS", SeverityHigh, 100, base.String(), "TLS", 0, "Certificate becomes valid at "+summary.NotBefore, "The target certificate NotBefore date is in the future.", "Deploy a currently valid certificate and verify system clock synchronization."))
	}
	if summary.SelfSigned {
		findings = append(findings, NewFinding("tls-self-signed-certificate", "Self-signed TLS certificate detected", "TLS", SeverityMedium, 95, base.String(), "TLS", 0, "Subject and issuer are both "+truncateString(summary.CertificateSubject, 180), "The leaf certificate appears to be self-signed.", "Use a certificate issued by a trusted internal or public CA and deploy the complete chain."))
	}
	if summary.HostnameMismatch {
		findings = append(findings, NewFinding("tls-hostname-mismatch", "TLS certificate hostname mismatch", "TLS", SeverityHigh, 100, base.String(), "TLS", 0, "Certificate hostname verification failed for "+base.Hostname(), "The certificate does not validate for the target hostname.", "Deploy a certificate whose SAN entries include the target hostname."))
	}
	legacy := checkLegacyTLS(ctx, cfg, base, address)
	summary.LegacyTLSSupported = legacy
	for _, version := range legacy {
		findings = append(findings, NewFinding("legacy-tls-supported-"+strings.ReplaceAll(strings.ToLower(version), " ", "-"), "Legacy TLS protocol appears supported", "TLS", SeverityMedium, 85, base.String(), "TLS", 0, "Handshake succeeded with "+version+".", "The server appears to support a legacy TLS protocol version.", "Disable TLS 1.0 and TLS 1.1 on the server or load balancer."))
	}
	return summary, findings
}

func checkLegacyTLS(ctx context.Context, cfg *Config, base *url.URL, address string) []string {
	var out []string
	checks := []struct {
		version uint16
		name    string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}}
	for _, ch := range checks {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		dialer := &net.Dialer{Timeout: minDuration(cfg.Timeout, 4*time.Second)}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: base.Hostname(), InsecureSkipVerify: true, MinVersion: ch.version, MaxVersion: ch.version})
		if err == nil {
			out = append(out, ch.name)
			conn.Close()
		}
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown 0x%x", v)
	}
}

func CheckHTTPToHTTPSRedirect(ctx context.Context, cfg *Config, base *url.URL) bool {
	httpURL := RootURL(base)
	httpURL.Scheme = "http"
	client := &http.Client{Timeout: minDuration(cfg.Timeout, 6*time.Second), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, httpURL.String(), nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Accept-Encoding", "identity")
		for _, kv := range cfg.CustomHeaders {
			req.Header.Set(kv.Name, kv.Value)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed && method == http.MethodHead {
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			parsed, err := url.Parse(loc)
			if err != nil {
				return false
			}
			resolved := httpURL.ResolveReference(parsed)
			return resolved.Scheme == "https" && sameHost(resolved, base)
		}
		return false
	}
	return false
}
