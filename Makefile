.PHONY: build-in-docker all test integ docker-release

all:
	cargo build

test:
	cargo test

integ:
	cargo test --features=integ-tests

build-in-docker:
	cargo clean
	mkdir -p ./target/release
	docker build -t make.local/synapse-builder:latest -f scripts/Dockerfile.build .
	docker run --user=$(shell id -u) -v "$(shell pwd)/target:/rust/app/target" make.local/synapse-builder:latest

docker-release:
	./scripts/build-push-docker-image
