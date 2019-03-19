all: lint test install_godet

install_godet:
	go install github.com/foae/godet/cmd/godet

lint:
	find . -path '*/vendor/*' -prune -o -name '*.go' -type f -exec gofmt -s -w {} \;
	which gometalinter; if [ $$? -ne 0 ]; then go get -u github.com/alecthomas/gometalinter && gometalinter --install; fi
	gometalinter --vendor --exclude=repos --disable-all --enable=golint ./...
	go vet ./...

test:
	go test -v ./...

run: install_godet
	APP_ENDPOINT_BLACKLIST="http://app.local/api/monitoring/blacklist/internal/log/bulk"
	APP_ENDPOINT_DETAILS="http://app.local/api/monitoring/details/internal/log/single"
	HTTP_SERVER_ACCESS_KEY="foobar"
	HTTP_SERVER_LISTEN_PORT="8888"
	$(GOPATH)/bin/godet