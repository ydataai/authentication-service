-include .env
export $(shell sed 's/=.*//' .env)

GOPATH=$(shell go env GOPATH)

.PHONY: help build fmt vet

help:	# The following lines will print the available commands when entering just 'make'. ⚠️ This needs to be the first target, ever
ifeq ($(UNAME), Linux)
	@grep -P '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
else
	@awk -F ':.*###' '$$0 ~ FS {printf "%15s%s\n", $$1 ":", $$2}' \
		$(MAKEFILE_LIST) | grep -v '@awk' | sort
endif

build:	### Build
	go build -o main -a main.go

fmt:	### Run go fmt against code
	go fmt ./...

vet:	### Run go vet against code
	go vet ./...

test: ### Runs application's tests in verbose mode
	go test -v ./pkg/...
