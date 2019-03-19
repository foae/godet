package details

import (
	"crypto/tls"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/satori/go.uuid"
	"github.com/sparrc/go-ping"
)

const (
	httpClientTimeout = time.Second * 30
)

var (
	// FuncMap defines the available operations for the `details` package.
	FuncMap = map[string]func(c Client, target string) (*Output, error){
		"http_quick":    httpShort,
		"http_details":  httpDetails,
		"https_quick":   httpsShort,
		"https_details": httpsDetails,
		"ping":          pingShort,
		"dkim":          dkimShort,
		"spf":           spfShort,
		"dmarc":         dmarcShort,
		"hostname":      hostnameShort,
		"asn":           geoASN,
		"country":       geoCountry,
		"mx":            mxShort,
		"smtp25":        smtp25,
		"smtp465":       smtp465,
		"smtp587":       smtp587,
		"imap143":       imap143,
		"imap993":       imap993,
		"pop3110":       pop3110,
		"pop3s995":      pop3995,
	}

	roughTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		IdleConnTimeout:       time.Second * 10,
		TLSHandshakeTimeout:   time.Second * 10,
		ResponseHeaderTimeout: time.Second * 10,
		ExpectContinueTimeout: time.Second * 10,
		DisableKeepAlives:     false,
		MaxConnsPerHost:       0,
		DisableCompression:    false,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   100,
	}
)

// Output defines the structure of a `details` operation.
type Output struct {
	ID         string        `json:"id"`
	OpName     string        `json:"op_name"`
	Target     string        `json:"target"`
	CreatedAt  time.Time     `json:"created_at"`
	Results    []string      `json:"results"`
	Details    []string      `json:"details"`
	OpSuccess  bool          `json:"op_success"`
	OpDuration time.Duration `json:"op_duration"`
}

// Client defines the available clients to perform details operations.
type Client struct {
	http       *http.Client
	https      *http.Client
	geoASN     *geoip2.Reader
	geoCountry *geoip2.Reader
}

// NewClient returns a new details client.
func NewClient() *Client {
	c := Client{}

	geoAsn, err := geoip2.Open(`maxmind_db/GeoLite2-ASN_20190108/GeoLite2-ASN.mmdb`)
	if err != nil {
		log.Fatalf("could not open db for asn: %v", err)
	}
	c.geoASN = geoAsn

	geoCountry, err := geoip2.Open(`maxmind_db/GeoLite2-Country_20190108/GeoLite2-Country.mmdb`)
	if err != nil {
		log.Fatalf("could not open db for asn: %v", err)
	}
	c.geoCountry = geoCountry

	c.http = &http.Client{
		Transport: roughTransport,
		Timeout:   httpClientTimeout,
	}

	c.https = &http.Client{
		Transport: roughTransport,
		Timeout:   httpClientTimeout,
	}

	return &c
}

// Close closes the open clients, if any.
func (c *Client) Close() {
	if err := c.geoASN.Close(); err != nil {
		log.Printf("details: could not close geoASN: %v", err)
	}
	if err := c.geoCountry.Close(); err != nil {
		log.Printf("details: could not close geoCountry: %v", err)
	}
}

// NewOutput returns a new Output populated with the provided parameters.
func NewOutput(target string, name string) *Output {
	return &Output{
		ID:        uuid.NewV4().String(),
		OpName:    name,
		Target:    target,
		CreatedAt: time.Now(),
		Results:   make([]string, 0),
		Details:   make([]string, 0),
		OpSuccess: false,
	}
}

// Finish fills any remaining details in relation to an Output.
func (o *Output) Finish() {
	o.OpDuration = time.Since(o.CreatedAt)
	o.OpSuccess = true

	if len(o.Results) == 0 || o.Results[0] == "" {
		o.OpSuccess = false
	}
}

// AppendResults allows appending multiple results to an existing Output.
func (o *Output) AppendResults(s string) {
	o.Results = append(o.Results, s)
}

// AppendDetails allows appending multiple results to an existing Output.
func (o *Output) AppendDetails(s string) {
	o.Details = append(o.Details, s)
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	switch {
	case ip == nil:
		return false
	case ip.To4() == nil:
		return false
	default:
		return true
	}
}

func isDomain(s string) bool {
	ok := govalidator.IsDNSName(s)
	if !ok {
		return ok
	}

	_, err := url.Parse("http://" + s)
	if err != nil {
		return false
	}

	return strings.Contains(s, ".")
}

func httpShort(c Client, target string) (*Output, error) {
	o := NewOutput(target, "http_short")
	defer o.Finish()

	res, err := c.http.Get(fmt.Sprintf("http://%v", target))
	if err != nil {
		return nil, fmt.Errorf("http: could not check (%v): %v", target, err)
	}

	o.AppendResults(fmt.Sprintf("%v", res.StatusCode))
	o.AppendDetails(res.Status)

	return o, nil
}

func httpDetails(c Client, target string) (*Output, error) {
	o := NewOutput(target, "http_details")
	defer o.Finish()

	res, err := c.http.Get(fmt.Sprintf("http://%v", target))
	if err != nil {
		return nil, fmt.Errorf("http: could not check (%v): %v", target, err)
	}

	o.AppendResults(fmt.Sprintf("%v", res.StatusCode))
	for k, vals := range res.Header {
		for _, val := range vals {
			o.AppendDetails(k + ": " + val)
		}
	}

	return o, nil
}

func httpsShort(c Client, target string) (*Output, error) {
	o := NewOutput(target, "https_short")
	defer o.Finish()

	res, err := c.https.Get(fmt.Sprintf("https://%v", target))
	if err != nil {
		return nil, fmt.Errorf("https: could not check (%v): %v", target, err)
	}

	o.AppendResults(fmt.Sprintf("%v", res.StatusCode))
	o.AppendDetails(res.Status)

	return o, nil
}

func httpsDetails(c Client, target string) (*Output, error) {
	o := NewOutput(target, "https_details")
	defer o.Finish()

	res, err := c.https.Get(fmt.Sprintf("https://%v", target))
	if err != nil {
		return nil, fmt.Errorf("httpsDetails: could not check (%v): %v", target, err)
	}

	o.AppendResults(fmt.Sprintf("%v", res.StatusCode))
	for k, vals := range res.Header {
		for _, val := range vals {
			o.AppendDetails(k + ": " + val)
		}
	}

	if res.TLS == nil {
		o.AppendDetails("Could not retrieve SSL details")
	}

	o.AppendDetails(fmt.Sprintf("TLS version: %v / Cipher suite: %v",
		res.TLS.Version,
		res.TLS.CipherSuite,
	))

	return o, nil
}

func pingShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "ping_short")
	defer o.Finish()

	//out, _ := exec.Command("ping", target, "-c 5", "-i 3", "-w 10").Output()
	//if strings.Contains(string(out), "Destination Host Unreachable") {
	//	fmt.Println("TANGO DOWN")
	//} else {
	//	fmt.Println("IT'S ALIVEEE")
	//}

	pinger, err := ping.NewPinger(target)
	if err != nil {
		return nil, fmt.Errorf("could not init pinger: %v", err)
	}
	pinger.Count = 3
	pinger.Timeout = time.Second * 10
	pinger.SetPrivileged(false)
	pinger.Run()
	s := pinger.Statistics()

	o.AppendResults(fmt.Sprintf("avg: %v", s.AvgRtt.String()))
	o.AppendDetails(fmt.Sprintf("min: %v, max: %v, avg: %v", s.MinRtt, s.MaxRtt, s.AvgRtt))

	return o, nil
}

func dkimShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "dkim_short")
	defer o.Finish()

	switch {
	case isIPv4(target):
		domains, err := net.LookupAddr(target)
		if err != nil {
			return nil, fmt.Errorf("dkim_short: lookup domain error for (%v): %v", target, err)
		}

		for _, domain := range domains {
			domain = strings.TrimRight(domain, ".")
			domain = "default._domainkey." + domain
			records, err := net.LookupTXT(domain)
			if err != nil {
				return nil, fmt.Errorf("dkim_short: error for (%v/%v): %v", target, domain, err)
			}

			for _, record := range records {
				if strings.Contains(record, "v=DKIM") {
					o.AppendResults(record)
					o.AppendDetails(domain + ": " + record)
				}
			}
		}
	case isDomain(target):
		records, err := net.LookupTXT(target)
		if err != nil {
			return nil, fmt.Errorf("dkim_short: error for (%v): %v", target, err)
		}

		for _, record := range records {
			if strings.Contains(record, "v=DKIM") {
				o.AppendResults(record)
				o.AppendDetails(target + ": " + record)
			}
		}
	default:
		return nil, fmt.Errorf("dkim_short: target type not supported: %v", target)
	}

	return o, nil
}

func dmarcShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "dmarc_short")
	defer o.Finish()

	switch {
	case isIPv4(target):
		domains, err := net.LookupAddr(target)
		if err != nil {
			return nil, fmt.Errorf("dmarc_short: lookup domain error for (%v): %v", target, err)
		}

		for _, domain := range domains {
			domain = strings.TrimRight(domain, ".")
			domain = "_dmarc." + domain
			records, err := net.LookupTXT(domain)
			if err != nil {
				return nil, fmt.Errorf("dmarc_short: error for (%v/%v): %v", target, domain, err)
			}

			for _, record := range records {
				if strings.Contains(record, "v=DMARC") {
					o.AppendResults(record)
					o.AppendDetails(domain + ": " + record)
				}
			}
		}
	case isDomain(target):
		records, err := net.LookupTXT(target)
		if err != nil {
			return nil, fmt.Errorf("dmarc_short: error for (%v): %v", target, err)
		}

		for _, record := range records {
			if strings.Contains(record, "v=DMARC") {
				o.AppendResults(record)
				o.AppendDetails(target + ": " + record)
			}
		}
	default:
		return nil, fmt.Errorf("dmarc_short: target type not supported: %v", target)
	}

	return o, nil
}

func spfShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "spf_short")
	defer o.Finish()

	switch {
	case isIPv4(target):
		domains, err := net.LookupAddr(target)
		if err != nil {
			return nil, fmt.Errorf("spf_short: lookup domain error for (%v): %v", target, err)
		}

		for _, domain := range domains {
			domain = strings.TrimRight(domain, ".")
			records, err := net.LookupTXT(domain)
			if err != nil {
				return nil, fmt.Errorf("spf_short: error for (%v/%v): %v", target, domain, err)
			}

			for _, record := range records {
				if strings.Contains(record, "v=spf1") {
					o.AppendResults(record)
					o.AppendDetails(domain + ": " + record)
				}
			}
		}
	case isDomain(target):
		records, err := net.LookupTXT(target)
		if err != nil {
			return nil, fmt.Errorf("spf_short: error for (%v): %v", target, err)
		}

		for _, record := range records {
			if strings.Contains(record, "v=spf1") {
				o.AppendResults(record)
				o.AppendDetails(target + ": " + record)
			}
		}
	default:
		return nil, fmt.Errorf("spf_short: target type not supported: %v", target)
	}

	return o, nil
}

func hostnameShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "hostname_short")
	defer o.Finish()

	switch {
	case isIPv4(target):
		resolvedNames, err := net.LookupAddr(target)
		if err != nil {
			return nil, fmt.Errorf("hostname: lookup domain error for (%v): %v", target, err)
		}

		for _, domain := range resolvedNames {
			domain = strings.TrimRight(domain, ".")
			o.AppendResults(domain)
			o.AppendDetails(fmt.Sprintf("%v resolved to %v", target, domain))
		}
	case isDomain(target):
		ips, err := net.LookupIP(target)
		if err != nil {
			return nil, fmt.Errorf("hostname: lookup IP error for (%v): %v", target, err)
		}

		for _, ip := range ips {
			o.AppendResults(ip.String())
			o.AppendDetails(fmt.Sprintf("%v resolved to %v", target, ip.String()))
		}
	}

	return o, nil
}

func geoASN(c Client, target string) (*Output, error) {
	o := NewOutput(target, "geo_asn")
	defer o.Finish()

	var ip net.IP
	switch {
	case isIPv4(target):
		ip = net.ParseIP(target)
	case isDomain(target):
		ips, err := net.LookupIP(target)
		if err != nil {
			return nil, fmt.Errorf("geo_asn: could not lookup target (%v): %v", target, err)
		}

		ip = ips[0]
	default:
		return nil, fmt.Errorf("geo_asn: could not resolve (%v) to IP or domain", target)
	}

	asn, err := c.geoASN.ASN(ip)
	if err != nil {
		return nil, fmt.Errorf("geo_asn: could not find ASN for target (%v): %v", target, err)
	}
	o.AppendResults(fmt.Sprintf("ASN%v, %v", asn.AutonomousSystemNumber, asn.AutonomousSystemOrganization))
	o.AppendDetails(fmt.Sprintf("ASN number: %v / ASN name: %v", asn.AutonomousSystemNumber, asn.AutonomousSystemOrganization))

	return o, nil
}

func geoCountry(c Client, target string) (*Output, error) {
	o := NewOutput(target, "geo_country")
	defer o.Finish()

	var ip net.IP
	switch {
	case isIPv4(target):
		ip = net.ParseIP(target)
	case isDomain(target):
		ips, err := net.LookupIP(target)
		if err != nil {
			return nil, fmt.Errorf("geo_country: could not lookup target (%v): %v", target, err)
		}

		ip = ips[0]
	default:
		return nil, fmt.Errorf("geo_country: could not resolve to IP or domain (%v)", target)
	}

	country, err := c.geoCountry.Country(ip)
	if err != nil {
		return nil, fmt.Errorf("geo_country: could not find Country for target (%v): %v", target, err)
	}
	o.AppendResults(country.Country.Names["en"])
	o.AppendDetails(fmt.Sprintf("%v / %v", country.Country.Names["en"], country.Continent.Names["en"]))

	return o, nil
}

func mxShort(_ Client, target string) (*Output, error) {
	o := NewOutput(target, "mx_short")
	defer o.Finish()

	switch {
	case isIPv4(target):
		domains, err := net.LookupAddr(target)
		if err != nil {
			return nil, fmt.Errorf("mx_short: could not lookup address for (%v): %v", target, err)
		}

		for _, domain := range domains {
			domain := strings.TrimRight(domain, ".")
			mxs, err := net.LookupMX(domain)
			if err != nil {
				return nil, fmt.Errorf("mx_short: could not lookupMX for (%v/%v): %v", target, domain, err)
			}

			for _, mx := range mxs {
				o.AppendResults(mx.Host)
				o.AppendDetails(fmt.Sprintf("%v has MX priority %v", mx.Host, mx.Pref))
			}
		}
	case isDomain(target):
		mxs, err := net.LookupMX(target)
		if err != nil {
			return nil, fmt.Errorf("mx_short: could not lookupMX for (%v): %v", target, err)
		}

		for _, mx := range mxs {
			o.AppendResults(mx.Host)
			o.AppendDetails(fmt.Sprintf("%v has priority %v", mx.Host, mx.Pref))
		}
	default:
		return nil, fmt.Errorf("mx_short: target type (%v) not handled in mx", target)
	}

	return o, nil
}

func genericSMTP(_ Client, target string, port string) (*Output, error) {
	var portName string

	switch port {
	case "25", "465", "587":
		portName = "smtp_" + port
	default:
		return nil, fmt.Errorf("genericSMTP: port not supported: %v", port)
	}

	o := NewOutput(target, portName)
	defer o.Finish()

	switch {
	case isIPv4(target):
		// Dial found the IP directly.
		cl, err := smtp.Dial(target + ":" + port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to SMTP on (%v) via (%v): %v", target+":"+port, target, err)
		}
		defer cl.Quit()
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", target+":"+port))
		o.AppendDetails(fmt.Sprintf("Connection to %v is OK on SMTP port %v", target, port))
	case isDomain(target):
		// Resolve MX record first.
		mxs, err := net.LookupMX(target)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not perform MX on (%v): %v", target, err)
		}
		preferredMX := mxs[0]
		preferredMX.Host = strings.TrimRight(preferredMX.Host, ".")

		// Dial found MX entry.
		cl, err := smtp.Dial(preferredMX.Host + ":" + port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to SMTP on (%v) via (%v): %v", preferredMX.Host, target, err)
		}
		defer cl.Quit()
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", target+port))
		o.AppendDetails(fmt.Sprintf("(%v) resolved to (%v); connection OK on SMTP port %v", target, preferredMX.Host, port))
	default:
		return nil, fmt.Errorf(portName+": unhandled target type: %v", target)
	}

	return o, nil
}

func smtp25(c Client, target string) (*Output, error) {
	port := "25"
	return genericSMTP(c, target, port)
}

func smtp465(c Client, target string) (*Output, error) {
	port := "465"
	return genericSMTP(c, target, port)
}

func smtp587(c Client, target string) (*Output, error) {
	port := "587"
	return genericSMTP(c, target, port)
}

func genericIMAP(_ Client, target string, port string) (*Output, error) {
	var portName string

	switch port {
	case "143", "993":
		portName = "imap_" + port
	default:
		return nil, fmt.Errorf("genericIMAP: port not supported: %v", port)
	}

	o := NewOutput(target, portName)
	defer o.Finish()

	switch {
	case isIPv4(target):
		// Dial found IP directly.
		cl, err := net.Dial("tcp", target+":"+port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to IMAP on (%v) via (%v): %v", target+":"+port, target, err)
		}
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", target+port))
		o.AppendDetails(fmt.Sprintf("Connection OK on %v IMAP port %v", target, port))
	case isDomain(target):
		// Resolve MX record first.
		mxs, err := net.LookupMX(target)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not perform MX on (%v): %v", target, err)
		}
		preferredMX := mxs[0]
		preferredMX.Host = strings.TrimRight(preferredMX.Host, ".")

		// Dial found MX entry.
		cl, err := net.Dial("tcp", preferredMX.Host+":"+port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to IMAP on (%v) via (%v): %v", preferredMX.Host, target, err)
		}
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", preferredMX.Host))
		o.AppendDetails(fmt.Sprintf("(%v) resolved to (%v); connection OK on IMAP port %v", target, preferredMX.Host, port))
	default:
		return nil, fmt.Errorf(portName+": unhandled target type: %v", target)
	}

	return o, nil
}

func imap143(c Client, target string) (*Output, error) {
	port := "143"
	return genericIMAP(c, target, port)
}

func imap993(c Client, target string) (*Output, error) {
	port := "993"
	return genericIMAP(c, target, port)
}

func pop3110(c Client, target string) (*Output, error) {
	port := "110"
	return genericPOP3(c, target, port)
}

func pop3995(c Client, target string) (*Output, error) {
	port := "995"
	return genericPOP3(c, target, port)
}

func genericPOP3(_ Client, target string, port string) (*Output, error) {
	var portName string

	switch port {
	case "110", "995":
		portName = "pop3_" + port
	default:
		return nil, fmt.Errorf("genericPOP3: port not supported: %v", port)
	}

	o := NewOutput(target, portName)
	defer o.Finish()

	switch {
	case isIPv4(target):
		// Dial found IP directly.
		cl, err := net.Dial("tcp", target+":"+port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to POP3 on (%v) via (%v): %v", target+":"+port, target, err)
		}
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", target+":"+port))
		o.AppendDetails(fmt.Sprintf("Connection OK on %v POP3 port %v", target, port))
	case isDomain(target):
		// Resolve MX record first.
		mxs, err := net.LookupMX(target)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not perform MX on (%v): %v", target, err)
		}
		preferredMX := mxs[0]
		preferredMX.Host = strings.TrimRight(preferredMX.Host, ".")

		// Dial found MX entry.
		cl, err := net.Dial("tcp", preferredMX.Host+":"+port)
		if err != nil {
			return nil, fmt.Errorf(portName+": could not connect to POP3 on (%v) via (%v): %v", preferredMX.Host, target, err)
		}
		defer cl.Close()

		o.AppendResults(fmt.Sprintf("%v - OK", preferredMX.Host))
		o.AppendDetails(fmt.Sprintf("(%v) resolved to (%v); connection OK on POP3 port %v", target, preferredMX.Host, port))
	default:
		return nil, fmt.Errorf(portName+": unhandled target type: %v", target)
	}

	return o, nil
}
