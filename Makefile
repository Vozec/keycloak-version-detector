# Keycloak Version Finder — Makefile
# Run `make help` for the target list.

BIN        := kcvf
PKG        := ./cmd/kcvf
DB         := pkg/kcfinger/db.json
PREFIX     ?= /usr/local
GOFLAGS    ?=
MIN        ?=          # e.g. make db-all MIN=12.0.0

.DEFAULT_GOAL := build

## build: compile the kcvf binary (embeds the current db.json)
.PHONY: build
build:
	go build $(GOFLAGS) -o $(BIN) $(PKG)

## install: install kcvf into $(PREFIX)/bin
.PHONY: install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

## fmt: gofmt all sources
.PHONY: fmt
fmt:
	gofmt -w pkg cmd

## vet: go vet
.PHONY: vet
vet:
	go vet ./...

## test: run unit tests
.PHONY: test
test:
	go test ./...

## check: fmt-check + vet + build (CI gate)
.PHONY: check
check: vet build
	@test -z "$$(gofmt -l pkg cmd)" || { echo "gofmt needed:"; gofmt -l pkg cmd; exit 1; }
	@echo "ok"

# ---- database building (writes $(DB); re-run `make build` to embed) ----

## db: source-only DB from GitHub tags (fast, ~1 min)
.PHONY: db
db:
	go run $(PKG) builddb -o $(DB) $(if $(MIN),-min $(MIN),)

## db-wellknown: refresh only the OIDC discovery field->version table
.PHONY: db-wellknown
db-wellknown:
	go run $(PKG) builddb wellknown -o $(DB)

## db-dist: augment DB with all theme files from Maven jars (heavy download)
.PHONY: db-dist
db-dist:
	go run $(PKG) builddb dist -o $(DB) $(if $(MIN),-min $(MIN),)

## db-all: source + discovery + dist in one shot (heavy; needs bandwidth)
.PHONY: db-all
db-all:
	go run $(PKG) builddb all -o $(DB) $(if $(MIN),-min $(MIN),)

## db-rebuild: build the full DB then re-embed it into the binary
.PHONY: db-rebuild
db-rebuild: db-all build

# ---- convenience ----

## run: detect a target — make run URL=https://sso.example.com/
.PHONY: run
run: build
	@test -n "$(URL)" || { echo "usage: make run URL=https://host/"; exit 2; }
	./$(BIN) -v $(ARGS) $(URL)

## enum: enumerate realms/info — make enum URL=https://sso.example.com/
.PHONY: enum
enum: build
	@test -n "$(URL)" || { echo "usage: make enum URL=https://host/"; exit 2; }
	./$(BIN) enum $(ARGS) $(URL)

## clean: remove the built binary
.PHONY: clean
clean:
	rm -f $(BIN)

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
