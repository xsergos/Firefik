.PHONY: openapi openapi-check cover cover-full cover-gate test-integration-docker cover-merge

openapi:
	swag init -g internal/api/server.go --parseDependency --parseInternal \
		-o internal/api/openapi/ --outputTypes json,yaml

openapi-check:
	@$(MAKE) openapi > /dev/null
	@git diff --exit-code -- internal/api/openapi/ || { \
		echo "ERROR: OpenAPI spec is out of date. Run 'make openapi' and commit the result."; \
		exit 1; \
	}

COVER_THRESHOLD ?= 80.0
COVER_PROFILE ?= cover.out
COVER_PACKAGES ?= $(shell go list ./... | grep -v 'controlplane/gen')

cover:
	go test -race -coverprofile=$(COVER_PROFILE) $(COVER_PACKAGES)
	@go tool cover -func=$(COVER_PROFILE) | tail -1

cover-full:
	go test -coverpkg=./... -coverprofile=$(COVER_PROFILE) $(COVER_PACKAGES)
	@go tool cover -func=$(COVER_PROFILE) | tail -1

cover-gate: cover
	@total=$$(go tool cover -func=$(COVER_PROFILE) | tail -1 | awk '{print $$3}' | tr -d '%'); \
	awk -v t="$$total" -v th="$(COVER_THRESHOLD)" 'BEGIN { \
		if (t+0 < th+0) { printf "coverage %.1f%% < threshold %.1f%%\n", t, th; exit 1 } \
		else { printf "coverage %.1f%% >= threshold %.1f%%\n", t, th } \
	}'

INTEGRATION_IMAGE ?= firefik-integration-test:dev
COVERAGE_DIR ?= $(CURDIR)/.coverage

test-integration-docker:
	@mkdir -p $(COVERAGE_DIR)
	docker build -f Dockerfile.test -t $(INTEGRATION_IMAGE) .
	docker run --rm \
		--cap-add=NET_ADMIN --cap-add=NET_RAW \
		--privileged \
		-v $(COVERAGE_DIR):/coverage \
		-v /var/run/docker.sock:/var/run/docker.sock \
		$(INTEGRATION_IMAGE)
	@echo "integration coverage written to $(COVERAGE_DIR)/integration.out + binary.out"

cover-merge:
	@if [ ! -f $(COVER_PROFILE) ] || [ ! -f $(COVERAGE_DIR)/integration.out ]; then \
		echo "missing $(COVER_PROFILE) or $(COVERAGE_DIR)/integration.out — run cover-full + test-integration-docker first"; \
		exit 1; \
	fi
	@awk 'BEGIN{mode=""} \
	  FNR==1 && $$1=="mode:" {mode=$$2; next} \
	  { key=$$1" "$$2; cnt=$$3+0; \
	    if (key in counts) { if (cnt > counts[key]) counts[key]=cnt } \
	    else { counts[key]=cnt; order[++n]=key } } \
	  END { print "mode: "mode; for (i=1; i<=n; i++) print order[i], counts[order[i]] }' \
	  $(COVER_PROFILE) $(COVERAGE_DIR)/integration.out \
	  $(if $(wildcard $(COVERAGE_DIR)/binary.out),$(COVERAGE_DIR)/binary.out,) \
	  > cover-merged.out
	@go tool cover -func=cover-merged.out | tail -1
