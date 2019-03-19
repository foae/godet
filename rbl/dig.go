package rbl

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// CheckTargetWithDig will perform a check using the OS's `dig` program.
// Note that `dig` must be installed.
func CheckTargetWithDig(target string) ([]*Result, error) {
	target = strings.TrimSpace(target)
	switch {
	case isIPv4(target):
		result, err := performDig(target, typeIPv4)
		if err != nil {
			log.Println(err)
		}
		return result, nil
	case isDomain(target):
		result, err := performDig(target, typeDomain)
		if err != nil {
			log.Println(err)
		}
		return result, nil
	default:
		log.Fatalf("CheckTargetWithDig: %v cannot be processed: neither a domain nor an IPv4", target)
	}

	return nil, fmt.Errorf("CheckTargetWithDig: no case to treat %v", target)
}

func performDig(target string, listType ListType) ([]*Result, error) {
	listToCheck := make([]string, 0)
	reversedTarget := target

	switch listType {
	case typeIPv4:
		listToCheck = IPv4List
		reversedTarget = reverseByDot(target)
	case typeDomain:
		listToCheck = DomainList
		reversedTarget = target
	default:
		log.Printf("performDig: operation not supported: %v", listType)
	}

	collectedResults := make([]*Result, 0)
	for _, rblAddr := range listToCheck {
		now := time.Now()
		fqdn := reversedTarget + "." + rblAddr

		output, err := exec.CommandContext(context.Background(), "dig", "+short", "-t", "a", fqdn, "@1.1.1.1").Output()
		if err != nil {
			log.Printf("could not check target (%v) in (%v): %v", target, rblAddr, err)
			continue
		}

		output = bytes.TrimSpace(output)
		r := &Result{
			OpDuration:       time.Since(now),
			Target:           target,
			BlacklistAddress: rblAddr,
			Blacklisted:      len(output) > 0,
			ResponseCode:     string(output),
		}
		log.Printf("(%v) was checked against (%v) and found (%v)/(%v) in (%v)",
			r.Target,
			r.BlacklistAddress,
			r.Blacklisted,
			r.ResponseCode,
			r.OpDuration,
		)

		collectedResults = append(collectedResults, r)
	}

	return collectedResults, nil
}

func checkTargetsWithDig(targets []string) ([]*Result, error) {
	var wg sync.WaitGroup
	collectedResults := make([]*Result, 0)

	for _, target := range targets {
		wg.Add(1)
		target := strings.TrimSpace(target)

		go func(target string) {
			defer wg.Done()
			switch {
			case isIPv4(target):
				results, err := performDig(target, typeIPv4)
				if err != nil {
					log.Println(err)
				}
				collectedResults = append(collectedResults, results...)
			case isDomain(target):
				results, err := performDig(target, typeDomain)
				if err != nil {
					log.Println(err)
				}
				collectedResults = append(collectedResults, results...)
			default:
				log.Fatalf("%v cannot be processed: neither a domain nor an IPv4", target)
			}
		}(target)
	}

	wg.Wait()
	return collectedResults, nil
}
