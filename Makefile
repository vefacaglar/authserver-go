# go-authserver — common developer tasks.
#
# Think of these as the project's `package.json` scripts:
#   make dev     -> run the server locally (like `pnpm run dev`)
#   make build   -> compile a binary
#   make test    -> run the test suite
#
# `make` with no target prints this help.

.DEFAULT_GOAL := help

BINARY    := authserver
PKG       := ./cmd/authserver
PORT      ?= 5175
DEMO_PORT ?= 8090

.PHONY: help dev run build start stop start-all stop-all logs test smoke vet check tidy clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

dev: ## Run the server with local-dev defaults (Ctrl-C to stop)
	@./scripts/dev.sh

build: ## Compile the server binary to ./authserver
	go build -o $(BINARY) $(PKG)

run: build ## Build then run the compiled binary in the foreground
	@AUTH_REQUIRE_HTTPS=$${AUTH_REQUIRE_HTTPS:-false} ./$(BINARY)

start: ## Run in the background, freeing port $(PORT) first (logs: /tmp/authserver.log)
	@$(MAKE) -s stop
	@AUTH_REQUIRE_HTTPS=$${AUTH_REQUIRE_HTTPS:-false} ./scripts/dev.sh > /tmp/authserver.log 2>&1 & echo $$! > .authserver.pid
	@sleep 1
	@echo "started in background (logs: /tmp/authserver.log); stop with 'make stop'"

stop: ## Stop the background server: pidfile + anything bound to port $(PORT)
	@if [ -f .authserver.pid ]; then kill $$(cat .authserver.pid) 2>/dev/null || true; rm -f .authserver.pid; fi
	@pids=$$(lsof -ti tcp:$(PORT) 2>/dev/null); \
	if [ -n "$$pids" ]; then kill $$pids 2>/dev/null || true; echo "freed port $(PORT) (killed: $$pids)"; \
	else echo "port $(PORT) already free"; fi

start-all: ## Background auth server + browser demo client (open http://localhost:$(DEMO_PORT))
	@$(MAKE) -s stop-all
	@AUTH_REQUIRE_HTTPS=$${AUTH_REQUIRE_HTTPS:-false} ./scripts/dev.sh > /tmp/authserver.log 2>&1 & echo $$! > .authserver.pid
	@sleep 2
	@AUTH_ISSUER=http://localhost:$(PORT) DEMO_ADDR=:$(DEMO_PORT) DEMO_REDIRECT_URI=http://localhost:$(DEMO_PORT)/callback \
		go run ./examples/loginflow > /tmp/democlient.log 2>&1 & echo $$! > .democlient.pid
	@sleep 2
	@echo "auth server : http://localhost:$(PORT)   (logs: /tmp/authserver.log)"
	@echo "demo client : http://localhost:$(DEMO_PORT)   (logs: /tmp/democlient.log)"
	@echo "==> open http://localhost:$(DEMO_PORT) and log in as demo/demo"
	@echo "    stop both with 'make stop-all'"

stop-all: ## Stop both the auth server and the demo client
	@$(MAKE) -s stop
	@if [ -f .democlient.pid ]; then kill $$(cat .democlient.pid) 2>/dev/null || true; rm -f .democlient.pid; fi
	@pids=$$(lsof -ti tcp:$(DEMO_PORT) 2>/dev/null); \
	if [ -n "$$pids" ]; then kill $$pids 2>/dev/null || true; echo "freed port $(DEMO_PORT) (killed: $$pids)"; \
	else echo "port $(DEMO_PORT) already free"; fi

logs: ## Tail the logs of both background services in real time (Ctrl-C to stop)
	@tail -f /tmp/authserver.log -f /tmp/democlient.log


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

clean: ## Remove build artifacts
	rm -f $(BINARY) .authserver.pid
