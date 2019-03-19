package godet

import (
	"fmt"
	"github.com/foae/godet/details"
	"log"
	"net/http"
)

// Router handles regular "please check this target" HTTP requests.
// It will also behave as a signaling controller
// between blacklist operations check and general
// details check(s) for an IP or domain (targets).
type Router struct {
	targetDetailsChan    chan string
	targetBlacklistsChan chan string
	announcementChan     chan interface{}
	accessKey            string
}

// NewRouter returns a new Router instance.
func NewRouter() *Router {
	return &Router{
		targetDetailsChan:    make(chan string),
		targetBlacklistsChan: make(chan string),
		announcementChan:     make(chan interface{}),
	}
}

// With amends the Router configuration by adding an access key.
func (rt *Router) With(accessKey string) {
	rt.accessKey = accessKey
}

func (rt *Router) signalingWorker(detailClient details.Client, cl *http.Client) {
	log.Println("Running signaling worker...")
	for {
		select {
		case target := <-rt.targetDetailsChan:
			go runGetDetails(detailClient, rt.announcementChan, target)
		case target := <-rt.targetBlacklistsChan:
			go runGetBlacklists(rt.announcementChan, target)
		}
	}
}

func (rt *Router) handleIncomingTargetDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Println("Details: received HTTP request: " + r.URL.String())

	target := r.URL.Query().Get("target")
	if target == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accessKey := r.Header.Get("AccessKey")
	if rt.accessKey != "" && accessKey != rt.accessKey {
		log.Printf("Details: unauthorized HTTP request using AccessKey (%v): %v", accessKey, r.URL.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rt.targetDetailsChan <- target
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"msg":"OK"}`)
}

func (rt *Router) handleIncomingTargetBlacklists(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Println("Blacklist: received HTTP request: " + r.URL.String())

	target := r.URL.Query().Get("target")
	if target == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid target"}`)
	}

	accessKey := r.Header.Get("AccessKey")
	if rt.accessKey != "" && accessKey != rt.accessKey {
		log.Printf("Blacklist: unauthorized HTTP request using AccessKey (%v): %v", accessKey, r.URL.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rt.targetBlacklistsChan <- target
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"msg":"OK"}`)
}
