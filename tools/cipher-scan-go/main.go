package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
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
	Domain            string `json:"domain" csv:"domain"`
	SSLv3             string `json:"sslv3" csv:"sslv3"`
	TLS10             string `json:"tls10" csv:"tls10"`
	TLS11             string `json:"tls11" csv:"tls11"`
	TLS12             string `json:"tls12" csv:"tls12"`
	TLS13             string `json:"tls13" csv:"tls13"`
	CipherSSLv3       string `json:"cipher_sslv3,omitempty" csv:"cipher_sslv3"`
	CipherTLS10       string `json:"cipher_tls10,omitempty" csv:"cipher_tls10"`
	CipherTLS11       string `json:"cipher_tls11,omitempty" csv:"cipher_tls11"`
	CipherTLS12       string `json:"cipher_tls12,omitempty" csv:"cipher_tls12"`
	CipherTLS13       string `json:"cipher_tls13,omitempty" csv:"cipher_tls13"`
	CertExpiry        string `json:"cert_expiry,omitempty" csv:"cert_expiry"`
	CertDaysRemaining int    `json:"cert_days_remaining" csv:"cert_days_remaining"`
	ErrorSummary      string `json:"error_summary,omitempty" csv:"error_summary"`
}

type protocolCheck struct {
	name    string
	version uint16
}

var protocolMatrix = []protocolCheck{
	{name: "SSLv3", version: 0x0300},
	{name: "TLS1.0", version: tls.VersionTLS10},
	{name: "TLS1.1", version: tls.VersionTLS11},
	{name: "TLS1.2", version: tls.VersionTLS12},
	{name: "TLS1.3", version: tls.VersionTLS13},
}

func main() {
	var filePath string
	var concurrency int
	var timeoutSec int
	var output string
	var mando bool

	flag.StringVar(&filePath, "file", "", "Path to newline-delimited domains")
	flag.StringVar(&filePath, "f", "", "Path to newline-delimited domains")
	flag.IntVar(&concurrency, "concurrency", 20, "Number of workers")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout in seconds per domain")
	flag.StringVar(&output, "output", "table", "Output format: table, json, csv, html")
	flag.BoolVar(&mando, "m", false, "")
	flag.BoolVar(&mando, "mando", false, "")

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
			if (a == "-f" || a == "--file" || a == "--concurrency" || a == "--timeout" || a == "--output") && i+1 < len(args) {
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
		status, cipher, expiry, days, err := tryHandshake(domain, p.version, timeout)
		switch p.name {
		case "SSLv3":
			r.SSLv3, r.CipherSSLv3 = status, cipher
		case "TLS1.0":
			r.TLS10, r.CipherTLS10 = status, cipher
		case "TLS1.1":
			r.TLS11, r.CipherTLS11 = status, cipher
		case "TLS1.2":
			r.TLS12, r.CipherTLS12 = status, cipher
		case "TLS1.3":
			r.TLS13, r.CipherTLS13 = status, cipher
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

func tryHandshake(domain string, version uint16, timeout time.Duration) (status string, cipher string, expiry string, days int, err error) {
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
		if version == 0x0300 && strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			return "unsupported", "", "", -1, err
		}
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

func emitTable(results []scanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tSSLv3\tTLS1.0\tTLS1.1\tTLS1.2\tTLS1.3\tCERT DAYS\tCERT EXPIRY\tNOTES")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Domain, r.SSLv3, r.TLS10, r.TLS11, r.TLS12, r.TLS13, r.CertDaysRemaining, r.CertExpiry, r.ErrorSummary)
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
	fmt.Println("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>cipher-scan</title><style>body{font-family:Arial,sans-serif;margin:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;font-size:12px;text-align:left}th{background:#f2f2f2}code{white-space:pre-wrap}</style></head><body>")
	fmt.Println("<h1>cipher-scan report</h1><table><thead><tr><th>Domain</th><th>SSLv3</th><th>TLS1.0</th><th>TLS1.1</th><th>TLS1.2</th><th>TLS1.3</th><th>Cert days</th><th>Cert expiry</th><th>Notes</th></tr></thead><tbody>")
	for _, r := range results {
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>\n",
			htmlEscape(r.Domain), htmlEscape(r.SSLv3), htmlEscape(r.TLS10), htmlEscape(r.TLS11), htmlEscape(r.TLS12), htmlEscape(r.TLS13), r.CertDaysRemaining, htmlEscape(r.CertExpiry), htmlEscape(r.ErrorSummary))
	}
	fmt.Println("</tbody></table></body></html>")
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}
