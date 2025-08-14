.PHONY: build check staticcheck vulncheck deadcode fmt test vet

build: check test
	go build -o clamav-rest cmd/clamav-rest/*.go

check: staticcheck vulncheck deadcode gosec vet

staticcheck:
	go tool honnef.co/go/tools/cmd/staticcheck ./...

vulncheck:
	go tool golang.org/x/vuln/cmd/govulncheck ./...

deadcode:
	go tool golang.org/x/tools/cmd/deadcode -test ./...

gosec:
	go tool github.com/securego/gosec/v2/cmd/gosec --exclude-generated -terse ./...

vet:
	go vet ./...

test:
	go test ./...
