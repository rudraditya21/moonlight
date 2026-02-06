SHELL := /bin/sh
CARGO := cargo
FMT := rustfmt

.PHONY: all build run test perf fmt fmt-check clippy clean help

all: build

build:
	$(CARGO) build

run:
	$(CARGO) run

# Run all tests

test:
	$(CARGO) test --workspace

# Run performance gates (10k module index + search)

perf:
	$(CARGO) run -p modules --bin catalog_bench

perf-release:
	MOONLIGHT_PERF_INDEX_MS_COLD=1200 MOONLIGHT_PERF_INDEX_MS_WARM=300 MOONLIGHT_PERF_SEARCH_MS=30 \
		$(CARGO) run -p modules --bin catalog_bench --release

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
	@echo "  perf       Run performance gates"
	@echo "  perf-release  Run performance gates (release, tuned for i5/8GB)"
	@echo "  fmt        Format code (rustfmt)"
	@echo "  fmt-check  Check formatting"
	@echo "  clippy     Run clippy (warnings as errors)"
	@echo "  clean      Clean build artifacts"
