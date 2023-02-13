.PHONY: build install help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

build: ## Builds the container in a multi stage Dockerfile
	docker build -t ghcr.io/codingric/trivy-reporter .

install: ## Push image to github
	docker push ghcr.io/codingric/trivy-reporter