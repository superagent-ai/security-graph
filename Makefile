.PHONY: check integration build run
check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.git/*'))" || (echo 'Run gofmt'; exit 1)
	go vet ./...
	go build ./...
integration:
	./scripts/integration.sh
build:
	CGO_ENABLED=0 go build -trimpath -o bin/security-graph ./cmd/security-graph
run:
	go run ./cmd/security-graph serve

.PHONY: seed
seed:
	./scripts/seed-demo.sh
