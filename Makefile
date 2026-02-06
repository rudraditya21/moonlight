SHELL := /bin/sh
CARGO := cargo
FMT := rustfmt

.PHONY: all build run test fmt fmt-check clippy clean help

all: build

build:
	$(CARGO) build

run:
	$(CARGO) run

# Run all tests

test:
	$(CARGO) test --workspace

# Format the codebase in-place

fmt:
	$(CARGO) fmt

# Check formatting without modifying files

fmt-check:
	$(CARGO) fmt -- --check

# Run clippy with warnings as errors

clippy:
	$(CARGO) clippy -- -D warnings

clean:
	$(CARGO) clean

help:
	@echo "Targets:"
	@echo "  build      Build the workspace"
	@echo "  run        Run the moonlight binary"
	@echo "  test       Run tests"
	@echo "  fmt        Format code (rustfmt)"
	@echo "  fmt-check  Check formatting"
	@echo "  clippy     Run clippy (warnings as errors)"
	@echo "  clean      Clean build artifacts"
