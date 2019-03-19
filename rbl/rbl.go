package rbl

import (
	"context"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	typeIPv4   ListType = "IPv4"
	typeIPv6   ListType = "IPv6"
	typeDomain ListType = "domain"
)

// ListType defines the type of a RBL list.
type ListType string

// Result defines the result after running a `rbl` operation.
type Result struct {
	Target           string        `json:"target"`
	Blacklisted      bool          `json:"blacklisted"`
	ResponseCode     string        `json:"response_code"`
	BlacklistAddress string        `json:"blacklist_address"`
	OpDuration       time.Duration `json:"op_duration"`
}

// CheckTargets performs a check for a list of targets.
func CheckTargets(ctx context.Context, targets []string) ([]*Result, error) {
	cl := new(dns.Client)
	cl.ReadTimeout = time.Second * 5
	cl.DialTimeout = time.Second * 5
	cl.Timeout = time.Second * 5
	cl.WriteTimeout = time.Second * 5

	collectedResults := make([]*Result, 0)
	for _, target := range targets {
		results, err := CheckTarget(context.Background(), target, cl)
		if err != nil {
			log.Println(err)
		}

		for _, r := range results {
			log.Printf("target: %v | blacklisted: %v | list: %v | code: %v |  op: %v",
				target,
				r.Blacklisted,
				r.BlacklistAddress,
				r.ResponseCode,
				r.OpDuration,
			)
		}

		collectedResults = append(collectedResults, results...)
	}

	return collectedResults, nil
}

// CheckTarget performs a check for a single target.
func CheckTarget(ctx context.Context, target string, dnsClient *dns.Client) ([]*Result, error) {
	target = strings.TrimSpace(target)
	switch {
	case isIPv4(target):
		return checkSingleTarget(ctx, target, typeIPv4, dnsClient, IPv4List)
	case isDomain(target):
		return checkSingleTarget(ctx, target, typeDomain, dnsClient, DomainList)
	default:
		return nil, fmt.Errorf("%v is not supported", target)
	}
}

func checkSingleTarget(
	_ context.Context,
	target string,
	targetType ListType,
	dnsClient *dns.Client,
	listToCheck []string,
) ([]*Result, error) {
	results := make([]*Result, 0)
	for _, rblName := range listToCheck {

		targetReversed := reverseByDot(target)
		if targetType == typeDomain {
			// Don't reverse if it's a domain.
			targetReversed = target
		}

		fqdn := targetReversed + "." + rblName + "."

		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeA)
		m.RecursionDesired = true

		resp, dur, err := dnsClient.Exchange(m, "1.1.1.1:53")
		if err != nil {
			results = append(results, &Result{
				Blacklisted:      false,
				Target:           target,
				BlacklistAddress: rblName,
				OpDuration:       time.Second * 5,
			})

			msg := fmt.Sprintf("error checking (%v) at (%v) via (%v): %v", target, rblName, fqdn, err)
			log.Println(msg)
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			results = append(results, &Result{
				Blacklisted:      false,
				Target:           target,
				BlacklistAddress: rblName,
				OpDuration:       dur,
			})

			log.Printf("skipped (%v) via (%v): non-zero Rcode: %v", target, fqdn, resp.Rcode)
			continue
		}

		for _, answer := range resp.Answer {
			a, ok := answer.(*dns.A)
			if !ok {
				log.Printf("could not convert (%v) to dns.A type", answer.String())
				continue
			}

			results = append(results, &Result{
				Blacklisted:      true,
				Target:           target,
				BlacklistAddress: rblName,
				OpDuration:       dur,
				ResponseCode:     a.A.String(),
			})
		}
	}

	return results, nil
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

func reverseIPv4(target string) string {
	t := strings.Split(target, ".")
	out := ""
	for i := len(t) - 1; i >= 0; i-- {
		out += t[i] + "."
	}

	return out
}

func reverseByDot(target string) string {
	t := strings.Split(target, ".")
	if len(t) == 0 {
		return target
	}

	out := ""
	for i := len(t) - 1; i >= 0; i-- {
		if i == 0 {
			out += t[i]
		} else {
			out += t[i] + "."
		}
	}

	return out
}
