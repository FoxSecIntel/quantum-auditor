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
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	PQCCurveID        string   `json:"pqc_curve_id,omitempty" csv:"pqc_curve_id"`
	PQCCurveLabel     string   `json:"pqc_curve_label,omitempty" csv:"pqc_curve_label"`
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
	X25519MLKEM768 tls.CurveID = 0x11EC
)

var protocolMatrix = []protocolCheck{
	{name: "SSLv3", version: 0x0300},
	{name: "TLS1.0", version: tls.VersionTLS10},
	{name: "TLS1.1", version: tls.VersionTLS11},
	{name: "TLS1.2", version: tls.VersionTLS12},
	{name: "TLS1.3", version: tls.VersionTLS13},
}

func init() {
	fmt.Fprintln(os.Stderr, "\n=== PQC Scanner Diagnostics ===")
	if os.Getenv("PQC_SCANNER_RESTARTED") == "1" {
		fmt.Fprintln(os.Stderr, "[diag] ✅ Auto-restarted with PQC enabled")
	}
	fmt.Fprintf(os.Stderr, "[diag] Runtime Go version: %s\n", runtime.Version())
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Fprintf(os.Stderr, "[diag] Build Go version: %s\n", bi.GoVersion)
	} else {
		fmt.Fprintf(os.Stderr, "[diag] Build Go version: unavailable\n")
	}
	fmt.Fprintf(os.Stderr, "[diag] GODEBUG: %s\n", os.Getenv("GODEBUG"))
	fmt.Fprintf(os.Stderr, "[diag] X25519MLKEM768 constant: 0x%04x (%d)\n", uint16(X25519MLKEM768), uint16(X25519MLKEM768))
}

func goVersionAtLeast(majorReq, minorReq int) bool {
	v := strings.TrimPrefix(runtime.Version(), "go")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minorPart := parts[1]
	for i, ch := range minorPart {
		if ch < '0' || ch > '9' {
			minorPart = minorPart[:i]
			break
		}
	}
	minor, err2 := strconv.Atoi(minorPart)
	if err1 != nil || err2 != nil {
		return false
	}
	if major > majorReq {
		return true
	}
	if major < majorReq {
		return false
	}
	return minor >= minorReq
}

func needsPQCRestart() bool {
	if os.Getenv("PQC_SCANNER_RESTARTED") == "1" {
		return false
	}
	if !goVersionAtLeast(1, 26) {
		return false
	}
	return !strings.Contains(os.Getenv("GODEBUG"), "tlsmlkem=1")
}

func withTLSMLKEMEnabled(godebug string) string {
	if godebug == "" {
		return "tlsmlkem=1"
	}
	if strings.Contains(godebug, "tlsmlkem=1") {
		return godebug
	}
	return godebug + ",tlsmlkem=1"
}

func restartWithPQC() {
	fmt.Fprintln(os.Stderr, "[info] Go 1.26+ detected. Restarting with GODEBUG=tlsmlkem=1 to enable PQC...")

	env := os.Environ()
	newEnv := make([]string, 0, len(env)+2)
	hasGoDebug := false
	hasMarker := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "GODEBUG=") {
			hasGoDebug = true
			cur := strings.TrimPrefix(kv, "GODEBUG=")
			newEnv = append(newEnv, "GODEBUG="+withTLSMLKEMEnabled(cur))
			continue
		}
		if strings.HasPrefix(kv, "PQC_SCANNER_RESTARTED=") {
			hasMarker = true
			newEnv = append(newEnv, "PQC_SCANNER_RESTARTED=1")
			continue
		}
		newEnv = append(newEnv, kv)
	}
	if !hasGoDebug {
		newEnv = append(newEnv, "GODEBUG=tlsmlkem=1")
	}
	if !hasMarker {
		newEnv = append(newEnv, "PQC_SCANNER_RESTARTED=1")
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] Failed to get executable path: %v\n", err)
		fmt.Fprintf(os.Stderr, "[error] Please run: GODEBUG=tlsmlkem=1 %s\n", os.Args[0])
		os.Exit(1)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = newEnv
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[error] Failed to auto-enable PQC. Please run: GODEBUG=tlsmlkem=1 %s <domain>\n", os.Args[0])
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := syscall.Exec(exe, os.Args, newEnv); err != nil {
		fmt.Fprintf(os.Stderr, "[error] Failed to auto-enable PQC. Please run: GODEBUG=tlsmlkem=1 %s <domain>\n", os.Args[0])
		os.Exit(1)
	}
}

func main() {
	if needsPQCRestart() {
		restartWithPQC()
		return
	}

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

	warnIfGoVersionOld()

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
		fmt.Fprintln(os.Stderr, "Usage: cipher-scan [options] <domain> OR cipher-scan --file domains.txt")
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
			status, cipher, expiry, days, pqcReady, curveID, curveLabel, sans, err := checkPQC(domain, timeout)
			r.TLS13, r.CipherTLS13 = statusToBoolString(status), cipher
			r.PQCSupported = pqcReady
			r.PQCCurveID = curveID
			r.PQCCurveLabel = curveLabel
			if pqcReady {
				r.Confidence = "High (Handshake Verified)"
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

func warnIfGoVersionOld() {
	v := strings.TrimPrefix(runtime.Version(), "go")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return
	}
	major, err1 := strconv.Atoi(parts[0])
	minorPart := parts[1]
	for i, ch := range minorPart {
		if ch < '0' || ch > '9' {
			minorPart = minorPart[:i]
			break
		}
	}
	minor, err2 := strconv.Atoi(minorPart)
	if err1 != nil || err2 != nil {
		return
	}
	if major < 1 || (major == 1 && minor < 24) {
		fmt.Fprintf(os.Stderr, "Warning: running Go %s. PQC hybrid negotiation may be unavailable before Go 1.24.\n", runtime.Version())
	}
}

func pqcCurveLabel(curve tls.CurveID) string {
	switch curve {
	case X25519MLKEM768:
		return "X25519MLKEM768 (PQC)"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(curve))
	}
}

func isPQCCurve(curve tls.CurveID) bool {
	return curve == X25519MLKEM768
}

func checkPQC(domain string, timeout time.Duration) (status string, cipher string, expiry string, days int, pqcReady bool, curveID string, curveLabel string, sans []string, err error) {
	state, handshakeErr := tls13HandshakeWithCurves(domain, timeout)
	if handshakeErr != nil {
		return "failed", "", "", -1, false, "handshake-failed", "handshake-failed", nil, handshakeErr
	}

	curveID = fmt.Sprintf("0x%04x", uint16(state.CurveID))
	curveLabel = pqcCurveLabel(state.CurveID)
	pqcReady = isPQCCurve(state.CurveID)

	cipher = tls.CipherSuiteName(state.CipherSuite)
	if cipher == "" {
		cipher = fmt.Sprintf("0x%04x", state.CipherSuite)
	}

	fmt.Fprintf(os.Stderr, "[diag] %s TLS version: 0x%04x\n", domain, state.Version)
	fmt.Fprintf(os.Stderr, "[diag] %s Cipher suite: %s\n", domain, cipher)
	fmt.Fprintf(os.Stderr, "[diag] %s Negotiated curve: %s (%s)\n", domain, curveID, curveLabel)
	fmt.Fprintf(os.Stderr, "[diag] %s PQC negotiated: %t\n", domain, pqcReady)
	if !pqcReady {
		fmt.Fprintf(os.Stderr, "[diag] %s PQC not negotiated. Check Go version and GODEBUG (for example GODEBUG=tlsmlkem=0 disables ML-KEM).\n", domain)
	}

	days = -1
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		notAfter := leaf.NotAfter
		days = int(time.Until(notAfter).Hours() / 24)
		expiry = notAfter.Format(time.RFC3339)
		sans = append([]string{}, leaf.DNSNames...)
	}

	return "ok", cipher, expiry, days, pqcReady, curveID, curveLabel, sans, nil
}

func tls13HandshakeWithCurves(domain string, timeout time.Duration) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(domain, "443")
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
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
	fmt.Fprintln(w, "DOMAIN\tPQC_NEGOTIATED\tCURVE_ID\tCURVE_LABEL")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%t\t%s\t%s\n", r.Domain, r.PQCSupported, r.PQCCurveID, r.PQCCurveLabel)
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
	fmt.Println("<h1>cipher-scan report</h1><table><thead><tr><th>Domain</th><th>PQC Negotiated</th><th>Curve ID</th><th>Curve Label</th><th>TLS1.3</th><th>Cipher</th><th>Related Domains</th><th>Cert days</th><th>Cert expiry</th><th>Notes</th></tr></thead><tbody>")
	for _, r := range results {
		pqcCell := "false"
		if r.PQCSupported {
			pqcCell = "<span class=\"pqc-ready\">true</span>"
		}
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>\n",
			htmlEscape(r.Domain), pqcCell, htmlEscape(r.PQCCurveID), htmlEscape(r.PQCCurveLabel), htmlEscape(r.TLS13), htmlEscape(r.CipherTLS13), htmlEscape(sanPreview(r.SubjectAltNames)), r.CertDaysRemaining, htmlEscape(r.CertExpiry), htmlEscape(r.ErrorSummary))
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
