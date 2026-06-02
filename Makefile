# go-authserver — common developer tasks.
#
# Think of these as the project's `package.json` scripts:
#   make dev     -> run the server locally (like `pnpm run dev`)
#   make build   -> compile a binary
#   make test    -> run the test suite
#
# `make` with no target prints this help.

.DEFAULT_GOAL := help

BINARY := authserver
PKG    := ./cmd/authserver

.PHONY: help dev run build start stop test smoke vet check tidy clean db-reset

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

dev: ## Run the server with local-dev defaults (Ctrl-C to stop)
	@./scripts/dev.sh

build: ## Compile the server binary to ./authserver
	go build -o $(BINARY) $(PKG)

run: build ## Build then run the compiled binary in the foreground
	@AUTH_REQUIRE_HTTPS=$${AUTH_REQUIRE_HTTPS:-false} ./$(BINARY)

start: build ## Run the binary in the background (writes ./.authserver.pid)
	@AUTH_REQUIRE_HTTPS=$${AUTH_REQUIRE_HTTPS:-false} ./scripts/dev.sh & echo $$! > .authserver.pid
	@echo "started (pid $$(cat .authserver.pid)); stop with 'make stop'"

stop: ## Stop a background server started with 'make start'
	@if [ -f .authserver.pid ]; then \
		kill $$(cat .authserver.pid) 2>/dev/null && echo "stopped" || echo "not running"; \
		rm -f .authserver.pid; \
	else echo "no .authserver.pid (foreground server? press Ctrl-C in its terminal)"; fi

test: ## Run the full test suite
	go test ./...

smoke: ## Run the build-tagged real-OIDC-client smoke test
	RUN_SMOKE=1 go test -tags m8smoke -v -count=1 -run TestSmoke_RealOIDCClient ./test/...

vet: ## Run go vet
	go vet ./...

check: vet test ## Run vet + tests (use before committing)
	go build ./...

tidy: ## Tidy go.mod / go.sum
	go mod tidy

db-reset: ## Delete the local dev SQLite database
	rm -f dev.db dev.db-shm dev.db-wal
	@echo "dev.db removed; it will be recreated + migrated on next 'make dev'"

clean: ## Remove build artifacts and the dev database
	rm -f $(BINARY) dev.db dev.db-shm dev.db-wal .authserver.pid
