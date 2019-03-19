package godet

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/foae/godet/details"
	"github.com/foae/godet/rbl"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	httpClientTimeout = time.Second * 30
)

var (
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
		DisableCompression:    true,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   100,
	}
)

func main() {
	log.Println("Starting up...")

	rblURL := os.Getenv("APP_ENDPOINT_BLACKLIST")
	if rblURL == "" {
		log.Fatal("APP_ENDPOINT_BLACKLIST is empty")
	}
	detailsURL := os.Getenv("APP_ENDPOINT_DETAILS")
	if detailsURL == "" {
		log.Fatal("APP_ENDPOINT_DETAILS is empty")
	}
	if os.Getenv("HTTP_SERVER_ACCESS_KEY") == "" {
		log.Fatal("HTTP_SERVER_ACCESS_KEY is empty")
	}
	port := os.Getenv("HTTP_SERVER_LISTEN_PORT")
	if port == "" {
		log.Println("HTTP_SERVER_LISTEN_PORT is empty, using default 8888 port.")
		port = "8888"
	}

	r := NewRouter()
	accessKey := os.Getenv("HTTP_SERVER_ACCESS_KEY")
	if detailsURL == "" {
		log.Fatal("HTTP_SERVER_ACCESS_KEY is empty")
	}
	r.With(accessKey)

	detailsClient := details.NewClient()
	defer detailsClient.Close()

	httpClient := &http.Client{
		Transport: roughTransport,
		Timeout:   httpClientTimeout,
	}

	// Any job finished will forward its results to another worker
	// which will make a HTTP POST back to our dashboard.
	go announcementWorker(httpClient, r.announcementChan, detailsURL, rblURL)

	// We also use router for signaling between go routines.
	go r.signalingWorker(*detailsClient, httpClient)

	// Define HTTP handlers.
	http.HandleFunc("/target/details", r.handleIncomingTargetDetails)
	http.HandleFunc("/target/blacklists", r.handleIncomingTargetBlacklists)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received (probing) HTTP request: " + r.URL.String())
		_, _ = fmt.Fprintf(w, `OK`)
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received (probing) HTTP request: " + r.URL.String())
		_, _ = fmt.Fprintf(w, `OK`)
	})

	// Run the local HTTP server.
	log.Printf("HTTP server is up on port (%v)", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, nil); err != nil {
		log.Fatalf("ListenAndServe on 127.0.0.1 port (%v) error: %v", port, err)
	}
}

func announcementWorker(
	cl *http.Client,
	ch chan interface{},
	detailsURL string,
	rblURL string,
) {
	log.Println("Running announcement worker...")
	for {
		select {
		case msgChan := <-ch:
			switch o := msgChan.(type) {

			case *details.Output:
				/*
					Details incoming
				*/
				outputJSON, err := json.Marshal(o)
				if err != nil {
					log.Printf("announcementWorker:details.Output: could not marshal JSON: %v", err)
					continue
				}

				go func() {
					resp, err := cl.Post(detailsURL, "application/json", bytes.NewReader(outputJSON))
					if err != nil {
						log.Printf("announcementWorker:details.Output: could not POST JSON to %v: %v", detailsURL, err)
						return
					}

					switch resp.StatusCode {
					case http.StatusOK, http.StatusNoContent, http.StatusCreated:
						// OK
					default:
						log.Printf("announcementWorker:details.Output: problem w/ (%v) POST to (%v): %v / %v", o.Target, detailsURL, resp.StatusCode, resp.Status)
					}
				}()

			case []*rbl.Result:
				/*
					RBL incoming
				*/
				rblJSON, err := json.Marshal(o)
				if err != nil {
					log.Printf("announcementWorker:rbl.Result: could not marshal RBL results: %v", err)
					continue
				}

				go func() {
					resp, err := cl.Post(rblURL, "application/json", bytes.NewReader(rblJSON))
					if err != nil {
						log.Printf("announcementWorker:rbl.Result: could not POST JSON to %v: %v", rblURL, err)
						return
					}

					switch resp.StatusCode {
					case http.StatusOK, http.StatusNoContent, http.StatusCreated:
						// OK
					default:
						log.Printf("announcementWorker:details.Output: problem w/ (%v) POST to (%v): %v / %v", o[0].Target, detailsURL, resp.StatusCode, resp.Status)
					}
				}()

			case error:
				log.Printf("announcementWorker:error: err in channel: %v", o)
			}
		}
	}
}

func runGetDetails(detailsClient details.Client, announceChan chan interface{}, target string) {
	for _, fn := range details.FuncMap {
		go func(
			exec func(d details.Client, t string) (*details.Output, error),
			t string,
		) {
			output, err := exec(detailsClient, target)
			switch {
			case err == nil:
				announceChan <- output
			case err != nil:
				announceChan <- err
			}
		}(fn, target)
	}
}

func runGetBlacklists(announceChan chan interface{}, target string) {
	rblResults, err := rbl.CheckTargetWithDig(target)
	if err != nil {
		announceChan <- err
		return
	}

	announceChan <- rblResults
}
