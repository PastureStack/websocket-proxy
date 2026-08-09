TARGETS := $(shell ls scripts)
DAPPER_IMAGE ?= pasturestack-websocket-proxy-dapper:ubuntu26
DAPPER_SOURCE ?= /go/src/github.com/PastureStack/websocket-proxy
DOCKER_VERSION ?= 29.6.2

.dapper-image: Dockerfile.dapper
	docker build \
		--network "$${DOCKER_BUILD_NETWORK:-host}" \
		--build-arg DAPPER_HOST_ARCH=$${DAPPER_HOST_ARCH:-amd64} \
		--build-arg DOCKER_VERSION=$(DOCKER_VERSION) \
		-t $(DAPPER_IMAGE) \
		-f Dockerfile.dapper .

$(TARGETS): .dapper-image
	docker run --rm \
		-v $(CURDIR):$(DAPPER_SOURCE) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-e DAPPER_UID=$$(id -u) \
		-e DAPPER_GID=$$(id -g) \
		-e ARCH=$${ARCH:-amd64} \
		-e DOCKER_BUILD_NETWORK \
		-e TAG \
		-e REPO \
		-e VERSION_OVERRIDE \
		-e SOURCE_DATE_EPOCH \
		$(DAPPER_IMAGE) $@

trash:
	@echo "Dependencies are vendored; no external dependency fetch is required."

trash-keep: trash

deps: trash

.DEFAULT_GOAL := ci

.PHONY: $(TARGETS) deps trash trash-keep
