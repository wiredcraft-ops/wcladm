.PHONY : all
all : build

.PHONY: build
build:
	go build -o _build/wcladm

.PHONY: linux
linux:
	env GOOS=linux GOARCH=amd64 go build -o _build/wcladm-linux-amd64
