package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

type scanResult struct {
	Domain            string   `json:"domain" csv:"domain"`
	SSLv3             string   `json:"sslv3" csv:"sslv3"`
	TLS10             string   `json:"tls10" csv:"tls10"`
	TLS11             string   `json:"tls11" csv:"tls11"`
	TLS12             string   `json:"tls12" csv:"tls12"`
	TLS13             string   `json:"tls13" csv:"tls13"`
	PQCSupported      bool     `json:"pqc_supported" csv:"pqc_supported"`
	PQCStrictCurve    string   `json:"pqc_strict_curve,omitempty" csv:"pqc_strict_curve"`
	PQCNormalCurve    string   `json:"pqc_normal_curve,omitempty" csv:"pqc_normal_curve"`
	Confidence        string   `json:"confidence,omitempty" csv:"confidence"`
	SubjectAltNames   []string `json:"subject_alt_names,omitempty" csv:"subject_alt_names"`
	CipherSSLv3       string   `json:"cipher_sslv3,omitempty" csv:"cipher_sslv3"`
	CipherTLS10       string   `json:"cipher_tls10,omitempty" csv:"cipher_tls10"`
	CipherTLS11       string   `json:"cipher_tls11,omitempty" csv:"cipher_tls11"`
	CipherTLS12       string   `json:"cipher_tls12,omitempty" csv:"cipher_tls12"`
	CipherTLS13       string   `json:"cipher_tls13,omitempty" csv:"cipher_tls13"`
	CertExpiry        string   `json:"cert_expiry,omitempty" csv:"cert_expiry"`
	CertDaysRemaining int      `json:"cert_days_remaining" csv:"cert_days_remaining"`
	ErrorSummary      string   `json:"error_summary,omitempty" csv:"error_summary"`
}

type protocolCheck struct {
	name    string
	version uint16
}

const (
	X25519MLKEM768       tls.CurveID = 0x11EC
	X25519Kyber768Draft0 tls.CurveID = 0x6399
)

var protocolMatrix = []protocolCheck{
	{name: "SSLv3", version: 0x0300},
	{name: "TLS1.0", version: tls.VersionTLS10},
	{name: "TLS1.1", version: tls.VersionTLS11},
	{name: "TLS1.2", version: tls.VersionTLS12},
	{name: "TLS1.3", version: tls.VersionTLS13},
}

func init() {
	// Force-enable Kyber/ML-KEM hybrid support in compatible Go runtimes.
	os.Setenv("GODEBUG", "tlskyber=1")
}

func main() {
	var filePath string
	var concurrency int
	var timeoutSec int
	var output string
	var mando bool
	var author bool

	flag.StringVar(&filePath, "file", "", "Path to newline-delimited domains")
	flag.StringVar(&filePath, "f", "", "Path to newline-delimited domains")
	flag.IntVar(&concurrency, "concurrency", 20, "Number of workers")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout in seconds per domain")
	flag.StringVar(&output, "output", "table", "Output format: table, json, csv, html")
	flag.BoolVar(&mando, "m", false, "")
	flag.BoolVar(&mando, "mando", false, "")
	flag.BoolVar(&author, "a", false, "Show author and repository details")

	cleanArgs, positional := preprocessArgs(os.Args[1:])
	if err := flag.CommandLine.Parse(cleanArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error initialising flags: %v\n", err)
		os.Exit(1)
	}

	if mando {
		decoded, _ := base64.StdEncoding.DecodeString("wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg==")
		fmt.Print(string(decoded))
		return
	}
	if author {
		fmt.Println("Author: FoxSecIntel")
		fmt.Println("Repository: https://github.com/FoxSecIntel/quantum-auditor")
		fmt.Println("Tool: cipher-scan (Go)")
		return
	}

	if concurrency < 1 {
		concurrency = 1
	}
	if timeoutSec < 5 {
		timeoutSec = 5
	}

	domains, err := loadDomains(filePath, positional)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initialising input: %v\n", err)
		os.Exit(1)
	}
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "No domains supplied. Use positional domain or --file.")
		os.Exit(1)
	}

	results := runWorkerPool(domains, concurrency, time.Duration(timeoutSec)*time.Second)

	switch strings.ToLower(output) {
	case "json":
		emitJSON(results)
	case "csv":
		emitCSV(results)
	case "html":
		emitHTML(results)
	default:
		emitTable(results)
	}
}

func preprocessArgs(args []string) ([]string, []string) {
	clean := make([]string, 0, len(args))
	positional := make([]string, 0, 1)
	skipNext := false

	for i := 0; i < len(args); i++ {
		if skipNext {
			skipNext = false
			continue
		}
		a := args[i]
		if strings.HasPrefix(a, "-") {
			clean = append(clean, a)
			if (a == "-f" || a == "--file" || a == "-file" ||
				a == "--concurrency" || a == "-concurrency" ||
				a == "--timeout" || a == "-timeout" ||
				a == "--output" || a == "-output" ||
				a == "--domain" || a == "-domain") && i+1 < len(args) {
				clean = append(clean, args[i+1])
				skipNext = true
			}
			continue
		}
		if len(positional) == 0 {
			positional = append(positional, a)
		} else {
			clean = append(clean, a)
		}
	}

	return clean, positional
}

func loadDomains(filePath string, positional []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	appendDomain := func(v string) {
		d := normaliseDomain(v)
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}

	if len(positional) > 0 {
		appendDomain(positional[0])
	}

	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			appendDomain(s.Text())
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func normaliseDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimSuffix(v, "/")
	if i := strings.Index(v, "/"); i > -1 {
		v = v[:i]
	}
	return v
}

func runWorkerPool(domains []string, workers int, timeout time.Duration) []scanResult {
	jobs := make(chan string)
	results := make(chan scanResult)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- scanDomain(d, timeout)
			}
		}()
	}

	go func() {
		for _, d := range domains {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]scanResult, 0, len(domains))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func scanDomain(domain string, timeout time.Duration) scanResult {
	r := scanResult{Domain: domain, CertDaysRemaining: -1}
	var allErrs []string

	for _, p := range protocolMatrix {
		if p.name == "TLS1.3" {
			status, cipher, expiry, days, pqcReady, strictCurve, normalCurve, sans, err := checkPQC(domain, timeout)
			r.TLS13, r.CipherTLS13 = statusToBoolString(status), cipher
			r.PQCSupported = pqcReady
			r.PQCStrictCurve = strictCurve
			r.PQCNormalCurve = normalCurve
			if pqcReady {
				r.Confidence = "High (Handshake Verified)"
				if strings.Contains(strictCurve, "Standard Hybrid (ML-KEM)") || strings.Contains(normalCurve, "Standard Hybrid (ML-KEM)") {
					r.Confidence = "High (Handshake Verified, Standard Hybrid (ML-KEM))"
				} else if strings.Contains(strictCurve, "Legacy Hybrid (Kyber)") || strings.Contains(normalCurve, "Legacy Hybrid (Kyber)") {
					r.Confidence = "High (Handshake Verified, Legacy Hybrid (Kyber))"
				}
			}
			r.SubjectAltNames = sans
			if r.CertExpiry == "" && expiry != "" {
				r.CertExpiry = expiry
				r.CertDaysRemaining = days
			}
			if err != nil {
				allErrs = append(allErrs, fmt.Sprintf("%s: %v", p.name, err))
			}
			continue
		}

		status, cipher, expiry, days, err := tryHandshake(domain, p.version, timeout)
		statusDisplay := statusToBoolString(status)
		switch p.name {
		case "SSLv3":
			r.SSLv3, r.CipherSSLv3 = statusDisplay, cipher
		case "TLS1.0":
			r.TLS10, r.CipherTLS10 = statusDisplay, cipher
		case "TLS1.1":
			r.TLS11, r.CipherTLS11 = statusDisplay, cipher
		case "TLS1.2":
			r.TLS12, r.CipherTLS12 = statusDisplay, cipher
		}
		if r.CertExpiry == "" && expiry != "" {
			r.CertExpiry = expiry
			r.CertDaysRemaining = days
		}
		if err != nil {
			allErrs = append(allErrs, fmt.Sprintf("%s: %v", p.name, err))
		}
	}

	if len(allErrs) > 0 {
		r.ErrorSummary = strings.Join(allErrs, " | ")
	}
	return r
}

func statusToBoolString(status string) string {
	if status == "ok" {
		return "true"
	}
	return "false"
}

func pqcCurvePreferences() []tls.CurveID {
	return []tls.CurveID{X25519MLKEM768, X25519Kyber768Draft0, tls.X25519, tls.CurveP256}
}

func pqcCurveLabel(curve tls.CurveID) string {
	switch curve {
	case X25519MLKEM768:
		return "Standard Hybrid (ML-KEM)"
	case X25519Kyber768Draft0:
		return "Legacy Hybrid (Kyber)"
	default:
		return ""
	}
}

func isPQCCurve(curve tls.CurveID) bool {
	return curve == X25519MLKEM768 || curve == X25519Kyber768Draft0
}

func checkPQC(domain string, timeout time.Duration) (status string, cipher string, expiry string, days int, pqcReady bool, strictCurve string, normalCurve string, sans []string, err error) {
	// Step 1: Strict PQC verification. Offer modern and legacy hybrid groups explicitly.
	strictState, strictErr := tls13HandshakeWithCurves(domain, timeout, []tls.CurveID{X25519MLKEM768, X25519Kyber768Draft0})
	if strictErr == nil {
		label := pqcCurveLabel(strictState.CurveID)
		if label != "" {
			strictCurve = fmt.Sprintf("0x%04x (%s)", uint16(strictState.CurveID), label)
		} else {
			strictCurve = fmt.Sprintf("0x%04x", uint16(strictState.CurveID))
		}
		pqcReady = isPQCCurve(strictState.CurveID)
	} else {
		strictCurve = fmt.Sprintf("handshake-failed: %v", strictErr)
	}

	// Step 2: Normal TLS 1.3 handshake for runtime posture and SAN extraction.
	state, normalErr := tls13HandshakeWithCurves(domain, timeout, pqcCurvePreferences())
	if normalErr != nil {
		if strictErr != nil {
			return "failed", "", "", -1, false, strictCurve, "handshake-failed", nil, fmt.Errorf("normal handshake failed: %v; strict PQC check failed: %v", normalErr, strictErr)
		}
		return "failed", "", "", -1, false, strictCurve, "handshake-failed", nil, normalErr
	}
	if label := pqcCurveLabel(state.CurveID); label != "" {
		normalCurve = fmt.Sprintf("0x%04x (%s)", uint16(state.CurveID), label)
	} else {
		normalCurve = fmt.Sprintf("0x%04x", uint16(state.CurveID))
	}

	cipher = tls.CipherSuiteName(state.CipherSuite)
	if cipher == "" {
		cipher = fmt.Sprintf("0x%04x", state.CipherSuite)
	}

	days = -1
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		notAfter := leaf.NotAfter
		days = int(time.Until(notAfter).Hours() / 24)
		expiry = notAfter.Format(time.RFC3339)
		sans = append([]string{}, leaf.DNSNames...)
	}

	return "ok", cipher, expiry, days, pqcReady, strictCurve, normalCurve, sans, nil
}

func tls13HandshakeWithCurves(domain string, timeout time.Duration, curves []tls.CurveID) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(domain, "443")
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}

	return conn.ConnectionState(), nil
}

func tryHandshake(domain string, version uint16, timeout time.Duration) (status string, cipher string, expiry string, days int, err error) {
	if version <= tls.VersionTLS11 {
		return tryLegacyProbe(domain, version, timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(domain, "443")
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         domain,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "failed", "", "", -1, err
	}
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		return "failed", "", "", -1, err
	}
	state := conn.ConnectionState()
	cipher = tls.CipherSuiteName(state.CipherSuite)
	if cipher == "" {
		cipher = fmt.Sprintf("0x%04x", state.CipherSuite)
	}

	if len(state.PeerCertificates) > 0 {
		notAfter := state.PeerCertificates[0].NotAfter
		days = int(time.Until(notAfter).Hours() / 24)
		expiry = notAfter.Format(time.RFC3339)
	} else {
		days = -1
	}

	return "ok", cipher, expiry, days, nil
}

func tryLegacyProbe(domain string, version uint16, timeout time.Duration) (status string, cipher string, expiry string, days int, err error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(domain, "443"), timeout)
	if err != nil {
		return "failed", "", "", -1, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	hello, err := legacyClientHello(domain, version)
	if err != nil {
		return "failed", "", "", -1, err
	}
	if _, err := conn.Write(hello); err != nil {
		return "failed", "", "", -1, err
	}

	resp := make([]byte, 5)
	n, err := io.ReadAtLeast(conn, resp, 5)
	if err != nil {
		return "failed", "", "", -1, err
	}
	if n == 5 {
		// 22 is Handshake (potential support), 21 is Alert (usually rejection).
		if resp[0] == 22 {
			return "ok", "legacy-probe", "", -1, nil
		}
		return "failed", "", "", -1, fmt.Errorf("legacy handshake rejected")
	}
	return "failed", "", "", -1, fmt.Errorf("no legacy response")
}

func legacyClientHello(serverName string, version uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	sessionID := []byte{}
	cipherSuites := []uint16{0x002f, 0x0035, 0xc02f, 0xc030, 0x000a}
	compressionMethods := []byte{0x00}

	host := []byte(serverName)
	sni := make([]byte, 0)
	// SNI extension
	sni = append(sni, 0x00, 0x00)
	serverNameListLen := 1 + 2 + len(host)
	extLen := 2 + serverNameListLen
	sni = append(sni, byte(extLen>>8), byte(extLen))
	sni = append(sni, byte(serverNameListLen>>8), byte(serverNameListLen))
	sni = append(sni, 0x00)
	sni = append(sni, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)

	extensions := sni

	body := make([]byte, 0)
	body = append(body, byte(version>>8), byte(version))
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)

	csLen := len(cipherSuites) * 2
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, cs := range cipherSuites {
		body = append(body, byte(cs>>8), byte(cs))
	}

	body = append(body, byte(len(compressionMethods)))
	body = append(body, compressionMethods...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 4)
	handshake[0] = 0x01
	handshakeLen := len(body)
	handshake[1] = byte(handshakeLen >> 16)
	handshake[2] = byte(handshakeLen >> 8)
	handshake[3] = byte(handshakeLen)
	handshake = append(handshake, body...)

	record := make([]byte, 5)
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:3], version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func emitTable(results []scanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tSSLv3\tTLS1.0\tTLS1.1\tTLS1.2\tTLS1.3\tPQC\tPQC STRICT\tPQC NORMAL\tCONFIDENCE\tRELATED DOMAINS\tCERT DAYS\tCERT EXPIRY\tNOTES")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Domain, r.SSLv3, r.TLS10, r.TLS11, r.TLS12, r.TLS13, r.PQCSupported, r.PQCStrictCurve, r.PQCNormalCurve, r.Confidence, sanPreview(r.SubjectAltNames), r.CertDaysRemaining, r.CertExpiry, r.ErrorSummary)
	}
	_ = w.Flush()
}

func emitJSON(results []scanResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

func emitCSV(results []scanResult) {
	w := csv.NewWriter(os.Stdout)
	t := reflect.TypeOf(scanResult{})
	headers := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		headers = append(headers, t.Field(i).Tag.Get("csv"))
	}
	_ = w.Write(headers)
	for _, r := range results {
		v := reflect.ValueOf(r)
		row := make([]string, 0, v.NumField())
		for i := 0; i < v.NumField(); i++ {
			row = append(row, fmt.Sprintf("%v", v.Field(i).Interface()))
		}
		_ = w.Write(row)
	}
	w.Flush()
}

func emitHTML(results []scanResult) {
	fmt.Println("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>cipher-scan</title><style>body{font-family:Arial,sans-serif;margin:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;font-size:12px;text-align:left}th{background:#f2f2f2}code{white-space:pre-wrap}.pqc-ready{color:#10b981;font-weight:700}</style></head><body>")
	fmt.Println("<h1>cipher-scan report</h1><table><thead><tr><th>Domain</th><th>SSLv3</th><th>TLS1.0</th><th>TLS1.1</th><th>TLS1.2</th><th>TLS1.3</th><th>PQC</th><th>PQC Strict</th><th>PQC Normal</th><th>Confidence</th><th>Related Domains</th><th>Cert days</th><th>Cert expiry</th><th>Notes</th></tr></thead><tbody>")
	for _, r := range results {
		pqcCell := "false"
		if r.PQCSupported {
			pqcCell = "<span class=\"pqc-ready\">true</span>"
		}
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>\n",
			htmlEscape(r.Domain), htmlEscape(r.SSLv3), htmlEscape(r.TLS10), htmlEscape(r.TLS11), htmlEscape(r.TLS12), htmlEscape(r.TLS13), pqcCell, htmlEscape(r.PQCStrictCurve), htmlEscape(r.PQCNormalCurve), htmlEscape(r.Confidence), htmlEscape(sanPreview(r.SubjectAltNames)), r.CertDaysRemaining, htmlEscape(r.CertExpiry), htmlEscape(r.ErrorSummary))
	}
	fmt.Println("</tbody></table></body></html>")
}

func sanPreview(sans []string) string {
	if len(sans) == 0 {
		return "-"
	}
	if len(sans) <= 3 {
		return strings.Join(sans, ", ")
	}
	return strings.Join(sans[:3], ", ") + ", ..."
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}
