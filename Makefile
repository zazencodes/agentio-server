# agentio server. build.env names the release and the source revision this tree was exported from;
# every build here is stamped with them, so `agentio-server version` matches the published binaries.
include build.env

LDFLAGS := -s -w -X agentio.sh/server/internal/server.Version=$(VERSION) -X agentio.sh/server/internal/server.Revision=$(REVISION)
PLATFORM ?= linux/$(shell go env GOARCH)

.PHONY: server test docker clean

## server: build bin/agentio-server
server:
	CGO_ENABLED=0 go build -C server -trimpath -ldflags "$(LDFLAGS)" -o ../bin/agentio-server ./cmd/agentio-server

## test: vet and race-test the protocol and the server
test:
	go vet ./protocol/... ./server/...
	go test -race ./protocol/... ./server/...

## docker: build the server image (PLATFORM=linux/amd64 for x86 servers)
docker:
	docker build -f deploy/docker/Dockerfile --platform $(PLATFORM) --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t agentio/server:$(VERSION) .

clean:
	rm -rf bin
